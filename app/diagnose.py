"""Zone diagnosis: compare what both nodes say they have with what their
UDP listeners actually answer.

Design constraints:

* Both snapshots and all UDP probes happen inside one bounded request.
  Nothing here touches the publish/sync paths and no lock is held while
  I/O is in flight, so publishing, syncing and in-zone resolution keep
  working during a diagnosis.
* A verdict is only produced from data of *one* version pair. If either
  node changes version while the diagnosis runs, the differing answers
  must not be stitched into a fault: every name becomes ``retest_required``.
  Versions only ever move forward, so "start serial == end serial" on
  both nodes proves no switch happened inside the window.
* One node timing out never hides the other node's result: both nodes are
  probed independently and their partial data is still returned.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

import httpx
from dnslib import DNSRecord, QTYPE, RCODE

from .config import settings
from .models import (
    DiagnoseResult,
    NameDiagnosisOut,
    NodeDiagnosisOut,
    SnapshotOut,
    UdpAnswerOut,
)
from .storage import storage

log = logging.getLogger("diagnose")

Records = Dict[str, List[str]]


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------ helpers
def parse_udp_addr(value: str, fallback_port: int) -> Tuple[str, int]:
    """Parse ``host:port`` (IPv6 literals in brackets also work)."""
    value = value.strip()
    if value.startswith("["):
        host, sep, port = value[1:].partition("]:")
        if sep:
            try:
                return host, int(port)
            except ValueError:
                return host, fallback_port
        return value.strip("[]"), fallback_port
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        return value, fallback_port
    try:
        return host, int(port)
    except ValueError:
        return host, fallback_port


def _sorted(addresses: Optional[Sequence[str]]) -> List[str]:
    return sorted(addresses or [])


def _fmt(snapshot: SnapshotOut) -> str:
    if not snapshot.available:
        return "unavailable"
    if snapshot.addresses:
        return ", ".join(snapshot.addresses)
    return "no A record" if snapshot.found is False else "unknown"


# ------------------------------------------------------------------- probes
async def resolve_udp(
    host: str, port: int, timeout: float
) -> Tuple[Optional[Tuple], Optional[str]]:
    """Async getaddrinfo so name resolution never blocks the event loop."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM), timeout
        )
    except asyncio.TimeoutError:
        return None, f"cannot resolve {host}:{port} within {timeout:g}s"
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    if not infos:
        return None, f"cannot resolve {host}:{port}"
    family, socktype, proto, _, sockaddr = infos[0]
    return (family, socktype, proto, sockaddr), None


async def _query_udp_once(
    sockaddr: Tuple,
    family: int,
    socktype: int,
    proto: int,
    name: str,
    timeout: float,
) -> Tuple[Optional[DNSRecord], Optional[str]]:
    loop = asyncio.get_running_loop()
    question = DNSRecord.question(name, "A")
    question.header.rd = 0  # talking to an authoritative server
    sock = socket.socket(family, socktype, proto)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(
            loop.sock_sendto(sock, question.pack(), sockaddr), timeout
        )
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            data, sender = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 65535), remaining
            )
            if not _same_endpoint(sender, sockaddr):
                continue  # stray datagram from another peer
            try:
                reply = DNSRecord.parse(data)
            except Exception:
                continue  # malformed datagram, keep waiting
            if not reply.header.qr:
                continue  # a query, not a response
            if reply.header.id != question.header.id:
                continue  # not an answer to *this* query
            if reply.q is not None and (
                str(reply.q.qname).rstrip(".").lower() != name
                or QTYPE.get(reply.q.qtype) != "A"
            ):
                continue
            return reply, None
    except asyncio.TimeoutError:
        return None, f"UDP timeout after {timeout:g}s"
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()


def _same_endpoint(a: Tuple, b: Tuple) -> bool:
    try:
        return str(a[0]) == str(b[0]) and int(a[1]) == int(b[1])
    except (IndexError, TypeError, ValueError):
        return True


def _answer_addresses(reply: DNSRecord) -> List[str]:
    out: List[str] = []
    for rr in reply.rr:
        if QTYPE.get(rr.rtype) != "A":
            continue
        try:
            out.append(ipaddress.ip_address(str(rr.rdata)).compressed)
        except ValueError:
            out.append(str(rr.rdata))
    return out


async def probe_node(
    host: str,
    port: int,
    name: str,
    budget: float,
    attempts: int = 1,
) -> UdpAnswerOut:
    """Send A queries to one node; never raise.

    ``responded`` tells a timeout apart from an empty answer (NODATA) or
    NXDOMAIN: only the former means nothing came back at all.
    """
    if budget <= 0:
        return UdpAnswerOut(responded=False,
                            error="diagnosis deadline exceeded")
    started = time.monotonic()
    resolved, err = await resolve_udp(host, port, min(budget, 1.0))
    if resolved is None:
        return UdpAnswerOut(responded=False, error=err)
    family, socktype, proto, sockaddr = resolved

    attempts = max(1, attempts)
    last_error: Optional[str] = None
    for _ in range(attempts):
        remaining = budget - (time.monotonic() - started)
        if remaining <= 0:
            break
        reply, err = await _query_udp_once(
            sockaddr, family, socktype, proto, name,
            min(settings.diagnose_udp_timeout, remaining),
        )
        if reply is not None:
            return UdpAnswerOut(
                responded=True,
                rcode=str(RCODE.get(reply.header.rcode)),
                addresses=_answer_addresses(reply),
            )
        last_error = err
    return UdpAnswerOut(responded=False, error=last_error)


async def fetch_snapshot(
    base_url: str, timeout: float
) -> Tuple[Optional[int], Optional[str], Records, Optional[str]]:
    """Read a node's current zone snapshot from that node's REST API.

    Returns ``(serial, published_at, records_by_name, error)``.
    """
    if not base_url:
        return None, None, {}, "peer API URL is not configured on this node"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            resp = await client.get(f"{base_url.rstrip('/')}/api/zone")
            resp.raise_for_status()
            payload = resp.json()
        serial = int(payload["serial"])
        records: Records = {}
        for rec in payload["records"]:
            key = str(rec["name"]).rstrip(".").lower()
            records.setdefault(key, []).append(
                ipaddress.ip_address(str(rec["ip"])).compressed
            )
        published_at = payload.get("published_at")
        return serial, published_at, records, None
    except Exception as exc:
        log.warning("snapshot read failed for %s: %s", base_url, exc)
        return None, None, {}, f"{type(exc).__name__}: {exc}"


def read_local_snapshot() -> Tuple[Optional[int], Optional[str], Records, None]:
    """Read this node's snapshot straight from its store.

    Used only as a fallback when the node cannot reach its own REST API
    (e.g. a port mapping mismatch). The response marks it as
    ``source="local"`` so it is not mistaken for an API read.
    """
    serial, records, published_at = storage.get_active_version()
    by_name: Records = {}
    for rec in records:
        key = str(rec["name"]).rstrip(".").lower()
        try:
            ip = ipaddress.ip_address(str(rec["ip"])).compressed
        except ValueError:
            ip = str(rec["ip"])
        by_name.setdefault(key, []).append(ip)
    return serial, published_at, by_name, None


# ---------------------------------------------------------------- verdicts
def _self_problem(
    snapshot: SnapshotOut, udp: UdpAnswerOut
) -> Optional[str]:
    """A node contradicts its own snapshot, independent of the peer."""
    if not snapshot.available or not udp.responded:
        return None  # unknown / timeout, reported elsewhere
    expected = _sorted(snapshot.addresses)
    if _sorted(udp.addresses) != expected:
        return (
            f"snapshot={_fmt(snapshot)} but UDP rcode={udp.rcode} "
            f"addresses={', '.join(udp.addresses) or 'none'}"
        )
    if snapshot.found:
        if udp.rcode != "NOERROR":
            return (
                f"snapshot={_fmt(snapshot)} but UDP rcode={udp.rcode} "
                "(expected NOERROR with an A answer)"
            )
        return None
    # Not in the snapshot. NXDOMAIN is the normal absence answer; an empty
    # NOERROR is also acceptable (empty non-terminal or NODATA), since
    # either way the node serves no address, which is what the snapshot
    # says. Anything else (an address would already have failed above)
    # is unexpected for an in-zone A query.
    if udp.rcode not in ("NXDOMAIN", "NOERROR"):
        return (
            f"snapshot={_fmt(snapshot)} but UDP rcode={udp.rcode} "
            "(expected NXDOMAIN for an absent in-zone name)"
        )
    return None


def decide_name(
    primary_snapshot: SnapshotOut,
    backup_snapshot: SnapshotOut,
    primary_udp: UdpAnswerOut,
    backup_udp: UdpAnswerOut,
) -> Tuple[str, str]:
    """Return ``(verdict, detail)`` for one name.

    Order matters and is documented in the README:

    1. UDP no response for any node (independently observable).
    2. A snapshot unreadable -> no comparison possible
       (``diagnosis_incomplete``).
    3. A node contradicts its own snapshot -> node answer abnormal.
    4. Different serials -> the lower node is behind (no cross-node
       comparison of UDP answers: they legitimately differ by version).
    5. Same serial but different snapshot content -> content mismatch.
    6. Otherwise consistent.
    """
    down = [
        role
        for role, answer in (
            ("primary", primary_udp),
            ("backup", backup_udp),
        )
        if not answer.responded
    ]
    if down:
        parts = []
        for role, answer, snap in (
            ("primary", primary_udp, primary_snapshot),
            ("backup", backup_udp, backup_snapshot),
        ):
            if answer.responded:
                parts.append(
                    f"{role} answered rcode={answer.rcode} addresses="
                    f"{', '.join(answer.addresses) or 'none'} "
                    f"(snapshot serial="
                    f"{snap.serial if snap.serial is not None else '?'})"
                )
            else:
                parts.append(f"{role}: {answer.error or 'no UDP response'}")
        return (
            "udp_no_response",
            f"no UDP response from {', '.join(down)}; partial result kept. "
            + "; ".join(parts),
        )

    if not primary_snapshot.available or not backup_snapshot.available:
        missing = [
            role
            for role, snap in (
                ("primary", primary_snapshot),
                ("backup", backup_snapshot),
            )
            if not snap.available
        ]
        errors = "; ".join(
            f"{role}: {snap.error}"
            for role, snap in (
                ("primary", primary_snapshot),
                ("backup", backup_snapshot),
            )
            if not snap.available
        )
        return (
            "diagnosis_incomplete",
            f"cannot read snapshot from {', '.join(missing)} ({errors}); "
            "content cannot be compared",
        )

    problems = []
    for role, snap, udp in (
        ("primary", primary_snapshot, primary_udp),
        ("backup", backup_snapshot, backup_udp),
    ):
        problem = _self_problem(snap, udp)
        if problem:
            problems.append(f"{role} {problem}")
    if problems:
        return "node_answer_abnormal", "; ".join(problems)

    p_serial = primary_snapshot.serial
    b_serial = backup_snapshot.serial
    if p_serial != b_serial:
        if b_serial is not None and p_serial is not None and b_serial < p_serial:
            return (
                "backup_behind",
                f"backup serial={b_serial} is behind primary serial="
                f"{p_serial}; primary={_fmt(primary_snapshot)}, "
                f"backup={_fmt(backup_snapshot)}",
            )
        return (
            "node_answer_abnormal",
            f"version pair is inconsistent: primary serial={p_serial}, "
            f"backup serial={b_serial}; primary={_fmt(primary_snapshot)}, "
            f"backup={_fmt(backup_snapshot)}",
        )

    if _sorted(primary_snapshot.addresses) != _sorted(
        backup_snapshot.addresses
    ):
        return (
            "content_mismatch",
            f"both nodes report serial={p_serial} but snapshot contents "
            f"differ: primary={_fmt(primary_snapshot)}, "
            f"backup={_fmt(backup_snapshot)}",
        )

    return (
        "consistent",
        f"serial={p_serial} on both nodes, snapshot and UDP answer agree: "
        + (", ".join(_sorted(primary_snapshot.addresses)) or "NXDOMAIN"),
    )


# -------------------------------------------------------------- orchestrate
class _NodeSnapshot:
    __slots__ = ("serial", "published_at", "records", "error", "source")

    def __init__(self, serial=None, published_at=None, records=None,
                 error=None, source="api"):
        self.serial = serial
        self.published_at = published_at
        self.records = records or {}
        self.error = error
        self.source = source

    def for_name(self, name: str) -> SnapshotOut:
        if self.error is not None or self.serial is None:
            return SnapshotOut(
                available=False, error=self.error, source=self.source
            )
        addresses = list(self.records.get(name, []))
        return SnapshotOut(
            serial=self.serial,
            published_at=self.published_at,
            found=bool(addresses),
            addresses=addresses,
            available=True,
            source=self.source,
        )


class Diagnoser:
    """Stateless diagnosis runner; concurrent calls are independent."""

    async def run(self, names: List[str]) -> DiagnoseResult:
        checked_at = _utcnow_iso()
        deadline = time.monotonic() + settings.diagnose_deadline

        primary_api = (
            settings.effective_self_api_url
            if settings.is_primary
            else settings.peer_api_url()
        )
        backup_api = (
            settings.peer_api_url()
            if settings.is_primary
            else settings.effective_self_api_url
        )
        peer_api = backup_api if settings.is_primary else primary_api
        primary_udp = parse_udp_addr(
            settings.primary_dns_addr, settings.dns_port
        )
        backup_udp = parse_udp_addr(
            settings.backup_dns_addr, settings.dns_port
        )
        api_budget = max(
            0.5,
            min(settings.diagnose_deadline * 0.5, settings.http_timeout),
        )

        async def snapshot(base_url: str) -> _NodeSnapshot:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _NodeSnapshot(error="diagnosis deadline exceeded")
            budget = max(0.5, min(api_budget, remaining))
            try:
                serial, pub, records, err = await asyncio.wait_for(
                    fetch_snapshot(base_url, budget), max(0.5, remaining)
                )
            except Exception as exc:  # defensive; fetch_snapshot catches
                serial, pub, records, err = (
                    None, None, {}, f"{type(exc).__name__}: {exc}"
                )
            return _NodeSnapshot(serial, pub, records, err, source="api")

        async def snapshot_own() -> _NodeSnapshot:
            own = await snapshot(settings.effective_self_api_url)
            if own.error is None:
                return own
            # The node's own REST API is unreachable (e.g. container port
            # mapping differs from API_PORT). Fall back to its local
            # store and mark the source so this is visible in the output.
            log.warning(
                "own API snapshot failed (%s); using local store", own.error
            )
            serial, pub, records, err = await asyncio.get_running_loop(
            ).run_in_executor(None, read_local_snapshot)
            return _NodeSnapshot(serial, pub, records, err, source="local")

        # -- start-of-window snapshots: both nodes, concurrently ---------
        own_start, peer_start = await asyncio.gather(
            snapshot_own(), snapshot(peer_api)
        )
        if settings.is_primary:
            p_start, b_start = own_start, peer_start
        else:
            b_start, p_start = own_start, peer_start

        # -- UDP probes: every (name, node) pair concurrently ------------
        remaining = max(0.0, deadline - time.monotonic())
        probe_budget = min(
            remaining,
            settings.diagnose_udp_timeout
            * max(1, settings.diagnose_udp_attempts),
        )
        tasks = []
        for name in names:
            for udp in (primary_udp, backup_udp):
                tasks.append(
                    probe_node(
                        *udp,
                        name,
                        budget=probe_budget,
                        attempts=settings.diagnose_udp_attempts,
                    )
                )
        probed = await asyncio.gather(*tasks, return_exceptions=True)
        answers: Dict[str, Tuple[UdpAnswerOut, UdpAnswerOut]] = {}
        for idx, name in enumerate(names):
            pair = []
            for answer in (probed[idx * 2], probed[idx * 2 + 1]):
                if isinstance(answer, UdpAnswerOut):
                    pair.append(answer)
                else:
                    pair.append(
                        UdpAnswerOut(
                            responded=False,
                            error=f"{type(answer).__name__}: {answer}",
                        )
                    )
            answers[name] = (pair[0], pair[1])

        # -- end-of-window snapshots: proves no version switch -----------
        if deadline - time.monotonic() > 0.05:
            own_end, peer_end = await asyncio.gather(
                snapshot_own(), snapshot(peer_api)
            )
            if settings.is_primary:
                p_end, b_end = own_end, peer_end
            else:
                b_end, p_end = own_end, peer_end
        else:
            p_end = b_end = _NodeSnapshot(
                error="diagnosis deadline exceeded"
            )

        change_reason: Optional[str] = None
        observed_change = False
        if p_start.serial is not None and b_start.serial is not None:
            if (
                p_end.error is None
                and b_end.error is None
                and (
                    p_end.serial != p_start.serial
                    or b_end.serial != b_start.serial
                )
            ):
                observed_change = True
                change_reason = (
                    "a node changed version during the diagnosis "
                    f"(start primary={p_start.serial} "
                    f"backup={b_start.serial}, "
                    f"end primary={p_end.serial} "
                    f"backup={b_end.serial}); answers from different "
                    "versions are not compared, rerun the check"
                )
            elif p_start.serial != b_start.serial and (
                p_end.error is not None or b_end.error is not None
            ):
                # Already skewed at the start and we could not verify the
                # window: a fault claim on differing answers would be unsafe.
                change_reason = (
                    "could not re-read the zone snapshots after probing "
                    f"({p_end.error or b_end.error}); a version switch "
                    "cannot be ruled out, rerun the check"
                )
        # An unreadable start snapshot is already handled per name by
        # decide_name (diagnosis_incomplete) or as a UDP timeout.

        results: List[NameDiagnosisOut] = []
        for name in names:
            p_snap = p_start.for_name(name)
            b_snap = b_start.for_name(name)
            p_udp, b_udp = answers[name]
            verdict, detail = decide_name(p_snap, b_snap, p_udp, b_udp)

            # An observed switch invalidates every comparison. An
            # unverifiable window only invalidates content comparisons:
            # a UDP timeout is a definite observation, so it is kept but
            # carries the caveat in its detail.
            if observed_change or (
                change_reason is not None
                and verdict != "udp_no_response"
            ):
                verdict = "retest_required"
                detail = f"{change_reason}. Observed before retest: {detail}"
            elif change_reason is not None:
                detail = f"{detail}. Caution: {change_reason}"

            results.append(
                NameDiagnosisOut(
                    name=name,
                    verdict=verdict,
                    detail=detail,
                    primary=NodeDiagnosisOut(
                        role="primary",
                        api_base=primary_api or "(not configured)",
                        snapshot=p_snap,
                        udp=p_udp,
                    ),
                    backup=NodeDiagnosisOut(
                        role="backup",
                        api_base=backup_api or "(not configured)",
                        snapshot=b_snap,
                        udp=b_udp,
                    ),
                )
            )

        return DiagnoseResult(
            zone=settings.dns_zone,
            checked_at=checked_at,
            versions_at_start={
                "primary": p_start.serial,
                "backup": b_start.serial,
            },
            versions_at_end={
                "primary": p_end.serial,
                "backup": b_end.serial,
            },
            retest_required=any(
                item.verdict == "retest_required" for item in results
            ),
            names=results,
        )


diagnoser = Diagnoser()
