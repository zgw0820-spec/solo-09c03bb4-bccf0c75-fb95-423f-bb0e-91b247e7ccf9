"""Unit tests for the diagnosis verdict logic (no network needed)."""
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Settings/storage are created at import time, so point them at a temp
# location before importing the app modules.
_TMP = tempfile.mkdtemp(prefix="diagnose-unit-")
os.environ.setdefault("DNS_ZONE", "internal.local")
os.environ.setdefault("DB_PATH", os.path.join(_TMP, "unit.db"))

from app.diagnose import (  # noqa: E402
    decide_name,
    parse_udp_addr,
    _NodeSnapshot,
    _answer_addresses,
)
from app.config import settings  # noqa: E402


def snap(serial, addresses=None, available=True, error=None):
    from app.models import SnapshotOut

    if not available:
        return SnapshotOut(available=False, error=error or "boom")
    addresses = addresses or []
    return SnapshotOut(
        serial=serial,
        found=bool(addresses),
        addresses=addresses,
        available=True,
    )


def udp(addresses=None, rcode=None, responded=True, error=None):
    from app.models import UdpAnswerOut

    addresses = addresses or []
    if rcode is None:
        rcode = "NOERROR" if addresses else "NXDOMAIN"
    return UdpAnswerOut(
        responded=responded,
        rcode=rcode if responded else None,
        addresses=addresses,
        error=error,
    )


def test_consistent_when_everything_matches():
    verdict, detail = decide_name(
        snap(5, ["10.0.0.1"]), snap(5, ["10.0.0.1"]),
        udp(["10.0.0.1"]), udp(["10.0.0.1"]),
    )
    assert verdict == "consistent"
    assert "serial=5" in detail


def test_consistent_when_name_absent_everywhere():
    # Absent in both snapshots, both answer NXDOMAIN -> consistent, not a
    # missing-name fault.
    verdict, _ = decide_name(
        snap(5), snap(5), udp(), udp(),
    )
    assert verdict == "consistent"


def test_backup_behind_when_serial_older():
    verdict, detail = decide_name(
        snap(7, ["10.0.0.2"]), snap(6, ["10.0.0.1"]),
        udp(["10.0.0.2"]), udp(["10.0.0.1"]),
    )
    assert verdict == "backup_behind"
    assert "serial=6" in detail and "serial=7" in detail


def test_same_serial_different_content_is_content_mismatch():
    verdict, detail = decide_name(
        snap(3, ["10.0.0.1"]), snap(3, ["10.0.0.9"]),
        udp(["10.0.0.1"]), udp(["10.0.0.9"]),
    )
    assert verdict == "content_mismatch"
    assert "10.0.0.1" in detail and "10.0.0.9" in detail


def test_node_contradicting_its_own_snapshot_is_abnormal():
    # Same serial and same snapshot, but the backup UDP answers a stale IP.
    verdict, detail = decide_name(
        snap(3, ["10.0.0.1"]), snap(3, ["10.0.0.1"]),
        udp(["10.0.0.1"]), udp(["10.0.0.66"]),
    )
    assert verdict == "node_answer_abnormal"
    assert "backup" in detail and "10.0.0.66" in detail


def test_nxdomain_from_node_that_snapshot_has_is_abnormal():
    # Snapshot has the name, UDP says NXDOMAIN: a self-contradiction.
    verdict, _ = decide_name(
        snap(3, ["10.0.0.1"]), snap(3, ["10.0.0.1"]),
        udp(["10.0.0.1"]), udp([], rcode="NXDOMAIN"),
    )
    assert verdict == "node_answer_abnormal"


def test_absent_name_accepts_nodata_or_nxdomain():
    # A name without an A record may legitimately be NODATA (empty
    # non-terminal) or NXDOMAIN; both agree with the snapshot.
    for rcode in ("NXDOMAIN", "NOERROR"):
        verdict, _ = decide_name(
            snap(3), snap(3),
            udp([], rcode=rcode), udp([], rcode=rcode),
        )
        assert verdict == "consistent", rcode


def test_absent_name_with_unexpected_rcode_is_abnormal():
    verdict, _ = decide_name(
        snap(3), snap(3),
        udp([], rcode="SERVFAIL"), udp([], rcode="SERVFAIL"),
    )
    assert verdict == "node_answer_abnormal"


def test_udp_no_response_keeps_the_other_node_result():
    verdict, detail = decide_name(
        snap(4, ["10.0.0.1"]), snap(4, ["10.0.0.1"]),
        udp(["10.0.0.1"]),
        udp(responded=False, error="UDP timeout after 1s"),
    )
    assert verdict == "udp_no_response"
    assert "backup" in detail
    # The reachable node's answer is spelled out in the detail.
    assert "10.0.0.1" in detail


def test_udp_no_response_primary_still_reports_backup_answer():
    verdict, detail = decide_name(
        snap(4, ["10.0.0.1"]), snap(4, ["10.0.0.1"]),
        udp(responded=False, error="UDP timeout after 1s"),
        udp(["10.0.0.1"]),
    )
    assert verdict == "udp_no_response"
    assert "primary" in detail and "10.0.0.1" in detail


def test_unreadable_snapshot_is_incomplete_not_a_fault():
    verdict, detail = decide_name(
        snap(4, ["10.0.0.1"]),
        snap(4, available=False, error="ConnectError"),
        udp(["10.0.0.1"]), udp(["10.0.0.1"]),
    )
    assert verdict == "diagnosis_incomplete"
    assert "ConnectError" in detail
    assert "consistent" not in detail


def test_different_serials_never_compare_udp_across_versions():
    # A naive implementation would call the differing UDP answers a fault.
    # The verdict must be the lag, and the detail must not claim a
    # node self-contradiction.
    verdict, detail = decide_name(
        snap(9, ["10.0.0.9"]), snap(8, ["10.0.0.8"]),
        udp(["10.0.0.9"]), udp(["10.0.0.8"]),
    )
    assert verdict == "backup_behind"
    assert "abnormal" not in detail


def test_timeout_with_version_skew_is_still_a_timeout():
    verdict, _ = decide_name(
        snap(9, ["10.0.0.9"]), snap(8, ["10.0.0.8"]),
        udp(["10.0.0.9"]),
        udp(responded=False, error="UDP timeout after 1s"),
    )
    assert verdict == "udp_no_response"


def test_parse_udp_addr_forms():
    assert parse_udp_addr("primary:5053", 53) == ("primary", 5053)
    assert parse_udp_addr("10.0.0.1:5053", 53) == ("10.0.0.1", 5053)
    assert parse_udp_addr("10.0.0.1", 5353) == ("10.0.0.1", 5353)
    assert parse_udp_addr("host:", 5353) == ("host", 5353)
    assert parse_udp_addr("host:notaport", 5353) == ("host", 5353)
    assert parse_udp_addr("[::1]:5053", 53) == ("::1", 5053)
    assert parse_udp_addr("[::1]", 53) == ("::1", 53)


def test_answer_addresses_ignores_non_a_records():
    from dnslib import A, AAAA, DNSRecord, QTYPE, RR

    q = DNSRecord.question("db.internal.local", "A")
    reply = q.reply()
    reply.add_answer(RR(q.q.qname, QTYPE.A, rdata=A("10.0.0.1"), ttl=30))
    reply.add_answer(
        RR(q.q.qname, QTYPE.AAAA, rdata=AAAA("2001:db8::1"), ttl=30)
    )
    assert _answer_addresses(reply) == ["10.0.0.1"]


def test_snapshot_out_for_name_marks_absence_and_errors():
    ok = _NodeSnapshot(2, None, {"db.internal.local": ["10.0.0.1"]})
    present = ok.for_name("db.internal.local")
    assert present.available and present.found is True
    assert present.addresses == ["10.0.0.1"]
    missing = ok.for_name("nope.internal.local")
    assert missing.available and missing.found is False

    bad = _NodeSnapshot(error="ConnectError: refused")
    unavailable = bad.for_name("db.internal.local")
    assert unavailable.available is False
    assert unavailable.found is None
    assert "ConnectError" in unavailable.error


def test_model_rejects_bad_diagnose_payloads():
    from pydantic import ValidationError

    from app.models import DiagnosePayload

    assert DiagnosePayload(names=["db.internal.local"]).names == [
        "db.internal.local"
    ]
    with pytest.raises(ValidationError):
        DiagnosePayload(names=[])
    with pytest.raises(ValidationError):
        DiagnosePayload(
            names=[f"h{i}.internal.local" for i in range(5)]
        )
    with pytest.raises(ValidationError):
        DiagnosePayload(names=["db.elsewhere.example"])
    with pytest.raises(ValidationError):
        DiagnosePayload(
            names=["db.internal.local", "DB.internal.local."]
        )
    # Normalisation: case, whitespace, trailing dot.
    assert DiagnosePayload(
        names=[" DB.INTERNAL.LOCAL. "]
    ).names == ["db.internal.local"]


def test_diagnosis_does_not_hog_the_event_loop():
    """A diagnosis against unresponsive peers must not starve other tasks.

    Publishing (threadpool), the backup sync loop and this ticker share
    the event loop, so a diagnosis that blocks it would stall them.
    """
    import asyncio
    import socket

    from app.diagnose import diagnoser

    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))
    silent_port = silent.getsockname()[1]
    silent.settimeout(2.0)  # holds the port but never answers

    ticks = 0

    async def ticker(stop: asyncio.Event):
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.02)

    async def scenario():
        stop = asyncio.Event()
        task = asyncio.create_task(ticker(stop))
        result = await diagnoser.run(
            ["db.internal.local", "web.internal.local"]
        )
        stop.set()
        await task
        return result

    old = {
        key: getattr(settings, key)
        for key in (
            "backup_api_url",
            "primary_api_url",
            "primary_dns_addr",
            "backup_dns_addr",
            "diagnose_udp_timeout",
            "diagnose_deadline",
            "http_timeout",
        )
    }
    try:
        object.__setattr__(
            settings, "primary_api_url", "http://127.0.0.1:9"
        )
        object.__setattr__(
            settings, "backup_api_url", "http://127.0.0.1:9"
        )
        object.__setattr__(
            settings, "primary_dns_addr", f"127.0.0.1:{silent_port}"
        )
        object.__setattr__(
            settings, "backup_dns_addr", f"127.0.0.1:{silent_port}"
        )
        object.__setattr__(settings, "diagnose_udp_timeout", 0.6)
        object.__setattr__(settings, "diagnose_deadline", 3.0)
        object.__setattr__(settings, "http_timeout", 1.0)
        result = asyncio.run(scenario())
    finally:
        silent.close()
        for key, value in old.items():
            object.__setattr__(settings, key, value)

    # Two names x two nodes, all timing out, still yielded the loop many
    # times: the ticker kept running instead of waiting for the probes.
    assert ticks > 20, ticks
    assert all(n.verdict == "udp_no_response" for n in result.names)
    assert all(
        n.primary.udp.responded is False and n.backup.udp.responded is False
        for n in result.names
    )
