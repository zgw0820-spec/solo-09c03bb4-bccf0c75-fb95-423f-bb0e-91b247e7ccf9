"""Pydantic models and zone validation rules shared by both roles."""
from __future__ import annotations

import ipaddress
import re
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from .config import settings

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def normalise_zone_name(value: str) -> str:
    """Normalise an FQDN and require it to belong to the fixed zone."""
    if not isinstance(value, str):
        raise ValueError("name must be a string")
    name = value.strip().rstrip(".").lower()
    zone = settings.dns_zone.rstrip(".").lower()
    if not name:
        raise ValueError("name must not be empty")
    if name != zone and not name.endswith("." + zone):
        raise ValueError(
            f"record {name!r} is outside the fixed zone {zone!r}"
        )
    owner = name[: -len("." + zone)] if name != zone else ""
    labels = owner.split(".") if owner else []
    if any(not _LABEL.match(label) for label in labels):
        raise ValueError(f"invalid owner name: {name!r}")
    return name


class RecordInput(BaseModel):
    name: str = Field(..., examples=["db.internal.local"])
    ip: str = Field(..., examples=["10.0.0.11"])

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("name must be a string")
        return v.strip().rstrip(".").lower()

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        try:
            ip = ipaddress.ip_address(v.strip())
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {v}") from exc
        if ip.version != 4:
            raise ValueError("only IPv4 A records are supported")
        return str(ip)


class ZonePayload(BaseModel):
    """A complete replacement of the fixed zone (max 8 A records)."""

    records: List[RecordInput]

    @model_validator(mode="after")
    def _validate_zone(self) -> "ZonePayload":
        if not self.records:
            raise ValueError("zone must contain at least one A record")
        if len(self.records) > settings.max_records:
            raise ValueError(
                f"a zone may contain at most {settings.max_records} A records"
            )
        zone = settings.dns_zone.rstrip(".").lower()
        suffix = "." + zone
        seen: set[str] = set()
        for rec in self.records:
            name = rec.name
            if name != zone and not name.endswith(suffix):
                raise ValueError(
                    f"record {name!r} is outside the fixed zone {zone!r}"
                )
            owner = name[: -len(suffix)] if name.endswith(suffix) else ""
            labels = owner.split(".") if owner else []
            if any(not _LABEL.match(label) for label in labels):
                raise ValueError(f"invalid owner name: {name!r}")
            if name in seen:
                raise ValueError(f"duplicate A record name: {name!r}")
            seen.add(name)
        return self

    def sorted_records(self) -> List[RecordInput]:
        return sorted(self.records, key=lambda r: r.name)


class RecordOut(BaseModel):
    name: str
    ip: str


class ZoneOut(BaseModel):
    zone: str
    serial: int
    records: List[RecordOut]
    published_at: Optional[str] = None


class VersionOut(BaseModel):
    role: str
    zone: str
    serial: int
    record_count: int
    published_at: Optional[str] = None
    last_sync_at: Optional[str] = None
    last_sync_status: str = "never"
    last_sync_error: Optional[str] = None
    upstream_serial: Optional[int] = None


class PublishResult(BaseModel):
    ok: bool
    serial: int
    record_count: int
    published_at: str


# ------------------------------------------------------------------ diagnosis
# Ordered from most to least specific; a name gets exactly one verdict.
Verdict = Literal[
    "consistent",            # same version, same snapshot answer, same UDP answer
    "backup_behind",         # primary version is newer than the backup's
    "content_mismatch",      # same serial, different snapshot content
    "node_answer_abnormal",  # snapshot and/or UDP answer disagree per node
    "udp_no_response",       # at least one UDP query timed out
    "retest_required",       # a version changed during the diagnosis
    "diagnosis_incomplete",  # a snapshot was unreadable; no comparison made
]


class DiagnosePayload(BaseModel):
    """At most four in-zone A names to check on both nodes."""

    names: List[str] = Field(
        ...,
        min_length=1,
        max_length=4,
        examples=[["db.internal.local", "web.internal.local"]],
    )

    @field_validator("names")
    @classmethod
    def _normalise_names(cls, values: List[str]) -> List[str]:
        names = [normalise_zone_name(v) for v in values]
        if len(set(names)) != len(names):
            raise ValueError("duplicate name in diagnosis request")
        return names


class SnapshotOut(BaseModel):
    """What one node's current zone snapshot says for a name.

    ``available`` is False when the node's snapshot could not be read; in
    that case the remaining fields are unknown rather than empty.
    ``source`` says whether the snapshot came from that node's REST API
    or, for the node running the diagnosis, from its local store (used
    only when its own API is not reachable).
    """

    serial: Optional[int] = None
    published_at: Optional[str] = None
    found: Optional[bool] = None
    addresses: Optional[List[str]] = None
    error: Optional[str] = None
    available: bool = True
    source: str = "api"


class UdpAnswerOut(BaseModel):
    """One raw UDP A answer (or the reason there was none).

    ``responded`` is False only when no datagram came back at all; an
    NXDOMAIN/NODATA reply is a response with ``responded=True``.
    """

    responded: bool
    rcode: Optional[str] = None
    addresses: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class NodeDiagnosisOut(BaseModel):
    role: str
    api_base: str
    snapshot: SnapshotOut
    udp: UdpAnswerOut


class NameDiagnosisOut(BaseModel):
    name: str
    verdict: Verdict
    detail: str
    primary: NodeDiagnosisOut
    backup: NodeDiagnosisOut


class DiagnoseResult(BaseModel):
    zone: str
    checked_at: str
    versions_at_start: dict
    versions_at_end: dict
    retest_required: bool
    names: List[NameDiagnosisOut]

