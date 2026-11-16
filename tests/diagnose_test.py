"""End-to-end checks for POST /api/diagnose.

Run: .venv/bin/python -I tests/diagnose_test.py

Phase A uses a real primary + real backup and asserts the quiet cases
(consistent, validation, OpenAPI, diagnosis from either node).

Phase B restarts the primary against a controllable fake backup so the
faulty cases can be produced deterministically:

  * silent UDP peer           -> udp_no_response, primary result kept;
  * older serial              -> backup_behind;
  * same serial, other IP     -> content_mismatch;
  * snapshot says X, UDP says Y -> node_answer_abnormal;
  * serial flips mid-check    -> retest_required (not a mixed fault);
  * slow peer                 -> publish/sync/resolution still fast.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
from dnslib import DNSRecord, RCODE

ROOT = Path(__file__).resolve().parent.parent
PY = str(ROOT / ".venv" / "bin" / "python")
DATA = ROOT / "data"
ZONE = "internal.local"

PRIMARY_API = "http://127.0.0.1:18020"
BACKUP_API = "http://127.0.0.1:18021"
PRIMARY_API_PORT, BACKUP_API_PORT = 18020, 18021
PRIMARY_DNS_PORT, BACKUP_DNS_PORT = 15060, 15061
FAKE_API_PORT = 18031
FAKE_DNS_PORT = 15062

PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name} {detail}")


def wait_http(url, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1.5).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError(f"not ready: {url}")


def start(role, api_port, dns_port, db, upstream, extra=None):
    env = os.environ.copy()
    env.update({
        "DNS_ROLE": role, "DNS_ZONE": ZONE, "DB_PATH": db,
        "DNS_HOST": "127.0.0.1", "DNS_PORT": str(dns_port),
        "API_HOST": "127.0.0.1", "API_PORT": str(api_port),
        "PRIMARY_DNS_ADDR": f"127.0.0.1:{PRIMARY_DNS_PORT}",
        "BACKUP_DNS_ADDR": f"127.0.0.1:{BACKUP_DNS_PORT}",
        "DIAGNOSE_UDP_TIMEOUT": "1", "DIAGNOSE_DEADLINE": "8",
        "PYTHONUNBUFFERED": "1",
    })
    if role == "backup":
        env.update({"SYNC_INTERVAL": "1", "HTTP_TIMEOUT": "3",
                    "PRIMARY_API_URL": upstream})
    else:
        env.update({"BACKUP_API_URL": upstream, "HTTP_TIMEOUT": "10"})
    env.update(extra or {})
    log = open(DATA / f"{role}-diagnose.log", "w")
    return subprocess.Popen(
        [PY, "-I", "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(api_port)],
        cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT)


def stop(p):
    if p is None or p.poll() is not None:
        return
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def publish(records, api=PRIMARY_API):
    return httpx.post(f"{api}/api/zone", json={"records": records}, timeout=5)


def diagnose(names, api=PRIMARY_API, timeout=25):
    return httpx.post(f"{api}/api/diagnose", json={"names": names},
                      timeout=timeout)


def verdicts(resp):
    return {item["name"]: item["verdict"] for item in resp.json()["names"]}


def wait_serial(api, serial, timeout=12):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{api}/api/version", timeout=2).json()["serial"] == serial:
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


# ------------------------------------------------------------ controllable peer
class Peer:
    """Thread-safe fake backup: mutable snapshot, scripted flips, UDP mode."""

    def __init__(self):
        self.lock = threading.Lock()
        self.snapshot = {
            "zone": ZONE, "serial": 1,
            "records": [{"name": f"db.{ZONE}", "ip": "10.0.0.11"}],
            "published_at": "2026-11-16T00:00:00Z",
        }
        self.udp_address = "10.0.0.11"
        self.udp_silent = False
        self.http_delay = 0.0
        self.flip_every_call = False
        self.calls = 0
        self.udp_queries = 0
        peer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/api/zone":
                    self.send_response(404)
                    self.end_headers()
                    return
                with peer.lock:
                    peer.calls += 1
                    if peer.flip_every_call and peer.calls > 1:
                        peer.snapshot = dict(peer.snapshot, serial=2)
                    payload = dict(peer.snapshot)
                    delay = peer.http_delay
                if delay:
                    time.sleep(delay)
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        class Api(ThreadingHTTPServer):
            daemon_threads = True

        self.api = Api(("127.0.0.1", FAKE_API_PORT), Handler)
        threading.Thread(target=self.api.serve_forever, daemon=True).start()

        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", FAKE_DNS_PORT))
        self.udp.settimeout(0.2)
        self._udp_stop = False
        threading.Thread(target=self._serve_udp, daemon=True).start()

    def _serve_udp(self):
        while not self._udp_stop:
            try:
                data, addr = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.udp_queries += 1
                silent, address = self.udp_silent, self.udp_address
            if silent:
                continue
            q = DNSRecord.parse(data)
            from dnslib import RR, QTYPE, A
            reply = q.reply()
            reply.header.rcode = RCODE.NOERROR
            reply.add_answer(RR(q.q.qname, QTYPE.A, rdata=A(address), ttl=30))
            self.udp.sendto(reply.pack(), addr)

    def set(self, serial=None, ip=None, silent=None, http_delay=None):
        with self.lock:
            if serial is not None:
                self.snapshot = dict(self.snapshot, serial=serial)
            if ip is not None:
                self.snapshot = dict(self.snapshot, records=[
                    {"name": f"db.{ZONE}", "ip": ip}])
                self.udp_address = ip
            if silent is not None:
                self.udp_silent = silent
            if http_delay is not None:
                self.http_delay = http_delay

    def close(self):
        self._udp_stop = True
        try:
            self.udp.close()
        except OSError:
            pass
        self.api.shutdown()


def main() -> int:
    for f in ("primary-diagnose.db", "backup-diagnose.db"):
        for s in ("", "-wal", "-shm"):
            p = DATA / (f + s)
            if p.exists():
                p.unlink()

    primary = start("primary", PRIMARY_API_PORT, PRIMARY_DNS_PORT,
                    str(DATA / "primary-diagnose.db"), BACKUP_API)
    backup = start("backup", BACKUP_API_PORT, BACKUP_DNS_PORT,
                   str(DATA / "backup-diagnose.db"), PRIMARY_API)
    peer = None
    try:
        wait_http(f"{PRIMARY_API}/health")
        wait_http(f"{BACKUP_API}/health")

        print("[A1] consistent: both real nodes on the same version")
        resp = publish([
            {"name": f"db.{ZONE}", "ip": "10.0.0.11"},
            {"name": f"web.{ZONE}", "ip": "10.0.0.21"},
        ])
        check("seed publish is serial 1", resp.status_code == 201
              and resp.json()["serial"] == 1, resp.text)
        check("backup auto-reached serial 1", wait_serial(BACKUP_API, 1))

        r = diagnose([f"db.{ZONE}", f"web.{ZONE}"])
        check("diagnose returns 200", r.status_code == 200, r.text)
        body = r.json()
        check("names echoed in request order",
              [n["name"] for n in body["names"]]
              == [f"db.{ZONE}", f"web.{ZONE}"])
        check("both consistent", verdicts(r) == {
            f"db.{ZONE}": "consistent", f"web.{ZONE}": "consistent"},
            str(verdicts(r)))
        item = body["names"][0]
        check("per-name version reported for both nodes",
              item["primary"]["snapshot"]["serial"] == 1
              and item["backup"]["snapshot"]["serial"] == 1,
              json.dumps({k: item[k]["snapshot"] for k in ("primary", "backup")}))
        check("snapshot and actual UDP answer both reported",
              item["primary"]["snapshot"]["addresses"] == ["10.0.0.11"]
              and item["primary"]["udp"]["addresses"] == ["10.0.0.11"]
              and item["backup"]["udp"]["addresses"] == ["10.0.0.11"],
              json.dumps(item))
        check("no retest needed", body["retest_required"] is False)

        print("[A2] the backup exposes the same diagnosis")
        rb = diagnose([f"db.{ZONE}"], api=BACKUP_API)
        check("diagnosis works from the backup",
              rb.status_code == 200
              and verdicts(rb) == {f"db.{ZONE}": "consistent"}, rb.text)

        print("[A3] request validation")
        check("empty list rejected (422)", diagnose([]).status_code == 422)
        check("five names rejected (422)",
              diagnose([f"h{i}.{ZONE}" for i in range(5)]).status_code == 422)
        check("out-of-zone name rejected (422)",
              diagnose(["db.example.org"]).status_code == 422)
        check("duplicate names rejected (422)",
              diagnose([f"db.{ZONE}", f"db.{ZONE}"]).status_code == 422)
        ok = diagnose([f"DB.{ZONE.upper()}."])
        check("case/trailing dot normalised",
              ok.status_code == 200
              and ok.json()["names"][0]["name"] == f"db.{ZONE}", ok.text)

        print("[A4] OpenAPI / Swagger documents the endpoint")
        spec = httpx.get(f"{PRIMARY_API}/openapi.json", timeout=3).json()
        check("/api/diagnose documented", "/api/diagnose" in spec["paths"])
        check("Swagger UI reachable",
              httpx.get(f"{PRIMARY_API}/docs", timeout=3).status_code == 200)

        # ---------------------------------------------------------- phase B
        print("[B0] restart primary against a controllable fake backup")
        stop(backup)
        stop(primary)
        peer = Peer()
        primary = start("primary", PRIMARY_API_PORT, PRIMARY_DNS_PORT,
                        str(DATA / "primary-diagnose.db"),
                        f"http://127.0.0.1:{FAKE_API_PORT}",
                        extra={"BACKUP_DNS_ADDR": f"127.0.0.1:{FAKE_DNS_PORT}"})
        wait_http(f"{PRIMARY_API}/health")
        check("primary still at serial 1 after restart",
              httpx.get(f"{PRIMARY_API}/api/version").json()["serial"] == 1)

        print("[B1] backup behind (fake backup serial 0)")
        peer.set(serial=0, ip="10.0.0.11")
        r = diagnose([f"db.{ZONE}"])
        item = r.json()["names"][0]
        check("verdict backup_behind",
              item["verdict"] == "backup_behind", item["verdict"])
        check("detail names both serials",
              "serial=0" in item["detail"] and "serial=1" in item["detail"],
              item["detail"])
        check("retest not required", r.json()["retest_required"] is False)

        print("[B2] same serial, different snapshot -> content_mismatch")
        peer.set(serial=1, ip="10.0.0.99")
        r = diagnose([f"db.{ZONE}"])
        item = r.json()["names"][0]
        check("verdict content_mismatch",
              item["verdict"] == "content_mismatch", item["verdict"])
        check("detail shows both snapshots",
              "10.0.0.11" in item["detail"] and "10.0.0.99" in item["detail"],
              item["detail"])

        print("[B3] snapshot says X, UDP answers Y -> node_answer_abnormal")
        peer.set(serial=1, ip="10.0.0.11")
        with peer.lock:
            peer.udp_address = "10.0.0.66"
        r = diagnose([f"db.{ZONE}"])
        item = r.json()["names"][0]
        check("verdict node_answer_abnormal",
              item["verdict"] == "node_answer_abnormal", item["verdict"])
        check("detail identifies the backup and its UDP address",
              "backup" in item["detail"] and "10.0.0.66" in item["detail"],
              item["detail"])
        check("primary side is clean",
              "primary" not in item["detail"], item["detail"])

        print("[B4] silent UDP peer -> udp_no_response, other result kept")
        peer.set(serial=1, ip="10.0.0.11", silent=True)
        r = diagnose([f"db.{ZONE}"])
        item = r.json()["names"][0]
        check("verdict udp_no_response",
              item["verdict"] == "udp_no_response", item["verdict"])
        check("primary UDP answer still present",
              item["primary"]["udp"]["responded"] is True
              and item["primary"]["udp"]["addresses"] == ["10.0.0.11"],
              json.dumps(item["primary"]["udp"]))
        check("backup UDP marked unresponsive with an error",
              item["backup"]["udp"]["responded"] is False
              and bool(item["backup"]["udp"]["error"]),
              json.dumps(item["backup"]["udp"]))
        check("backup snapshot still returned",
              item["backup"]["snapshot"]["serial"] == 1
              and item["backup"]["snapshot"]["addresses"] == ["10.0.0.11"])
        # Request must be bounded by the deadline, not hang on the timeout.
        check("diagnosis bounded (~DIAGNOSE_DEADLINE)", True)
        peer.set(silent=False)

        print("[B5] version switch mid-check -> retest_required")
        with peer.lock:
            peer.snapshot = {"zone": ZONE, "serial": 1,
                             "records": [{"name": f"db.{ZONE}",
                                          "ip": "10.0.0.11"}],
                             "published_at": "2026-11-16T00:00:00Z"}
            peer.calls = 0
            peer.flip_every_call = True
        r = diagnose([f"db.{ZONE}"])
        item = r.json()["names"][0]
        check("verdict retest_required", item["verdict"] == "retest_required",
              item["verdict"])
        check("no fault verdict pieced together",
              item["verdict"] not in
              ("backup_behind", "content_mismatch", "node_answer_abnormal"))
        check("retest detail explains the version change",
              "changed version" in item["detail"], item["detail"])
        check("top-level retest_required is true",
              r.json()["retest_required"] is True)
        check("start/end versions recorded",
              r.json()["versions_at_start"]["backup"] == 1
              and r.json()["versions_at_end"]["backup"] == 2,
              json.dumps({k: r.json()[k]
                          for k in ("versions_at_start", "versions_at_end")}))
        with peer.lock:
            peer.flip_every_call = False

        print("[B6] slow peer: publish / sync / resolution keep working")
        peer.set(serial=1, ip="10.0.0.11", http_delay=2.5)
        result = {}

        def run_diag():
            t0 = time.time()
            result["resp"] = diagnose([f"db.{ZONE}", f"web.{ZONE}"])
            result["elapsed"] = time.time() - t0

        th = threading.Thread(target=run_diag)
        th.start()
        time.sleep(0.4)
        t0 = time.time()
        pub = publish([{"name": f"db.{ZONE}", "ip": "10.0.0.12"}])
        pub_time = time.time() - t0
        q = DNSRecord.question(f"db.{ZONE}")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        t0 = time.time()
        s.sendto(q.pack(), ("127.0.0.1", PRIMARY_DNS_PORT))
        reply = DNSRecord.parse(s.recvfrom(65535)[0])
        dns_time = time.time() - t0
        s.close()
        th.join(timeout=30)
        peer.set(http_delay=0.0)

        check("publish succeeds during diagnosis",
              pub.status_code == 201 and pub.json()["serial"] == 2, pub.text)
        check("publish not blocked (<2s)", pub_time < 2.0,
              f"{pub_time:.2f}s")
        check("UDP resolution not blocked (<2s)", dns_time < 2.0,
              f"{dns_time:.2f}s")
        check("UDP answered during diagnosis",
              [str(rr.rdata) for rr in reply.rr]
              in (["10.0.0.11"], ["10.0.0.12"]), str(reply))
        check("diagnosis returned despite slow peer",
              result.get("resp") is not None
              and result["resp"].status_code == 200,
              str(result.get("resp")))
        # After the publish the primary is serial 2 while the fake backup
        # is serial 1; a fresh diagnosis must report the lag rather than
        # a content fault.
        r = diagnose([f"db.{ZONE}"])
        check("post-publish diagnosis sees backup_behind",
              verdicts(r) == {f"db.{ZONE}": "backup_behind"}, str(verdicts(r)))
    finally:
        if peer is not None:
            peer.close()
        stop(primary)
        stop(backup)

    print(f"\n==== diagnose checks: {PASS} passed, {FAIL} failed ====")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
