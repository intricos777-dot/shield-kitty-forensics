#!/usr/bin/env python3
"""
evidence.py — tamper-evident incident evidence store for Shield Kitty.

Every intrusion event is appended to a hash-chained log. Each record commits
to the previous record's hash, so altering or deleting any historical entry
invalidates every hash after it. `verify` proves the chain intact.

This is tamper-EVIDENT, not tamper-proof. An attacker with write access to
the store and the signing key can rebuild the chain from a truncation point.
That is why the sealing key is separate from the log and why `seal` writes
an anchor outside the log directory.

Commands:
  record   --event JSON      append one event to the chain
  verify                     check chain integrity, exit 1 if broken
  seal                      write a signed anchor (run on a schedule)
  bundle  --id ID            export a signed evidence bundle for one event
  report  --since HOURS      human-readable incident report
  list                       show recent events

Signing key: ~/.config/shield-kitty/evidence.key (0600, generated on first use)
Log store:   ~/.local/share/shield-kitty/evidence/
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

STORE = Path(os.environ.get("SHIELD_KITTY_STORE",
                            Path.home() / ".local/share/shield-kitty/evidence"))
KEYFILE = Path(os.environ.get("SHIELD_KITTY_KEY",
                              Path.home() / ".config/shield-kitty/evidence.key"))
CHAIN = STORE / "chain.jsonl"
ANCHOR = STORE / "anchor.json"

GENESIS = "0" * 64


# --- key handling ---------------------------------------------------------
def load_key() -> bytes:
    if not KEYFILE.exists():
        KEYFILE.parent.mkdir(parents=True, exist_ok=True)
        KEYFILE.write_bytes(secrets.token_bytes(32))
        KEYFILE.chmod(0o600)
    return KEYFILE.read_bytes()


def mac(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


# --- chain primitives -----------------------------------------------------
def read_chain() -> list[dict]:
    if not CHAIN.exists():
        return []
    out = []
    for line in CHAIN.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            # A corrupt line is itself evidence — keep it raw so verify flags it.
            out.append({"_corrupt": line})
    return out


def head_hash(records: list[dict]) -> str:
    return records[-1]["h"] if records else GENESIS


def write_record(rec: dict) -> dict:
    STORE.mkdir(parents=True, exist_ok=True)
    with CHAIN.open("a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def core_of(rec: dict) -> str:
    """Canonical string a record's hash is computed over."""
    payload = {k: v for k, v in rec.items() if k != "h"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def append_event(event: dict, source: str = "shield-kitty-watch") -> dict:
    key = load_key()
    records = read_chain()
    prev = head_hash(records)
    body = {
        "seq": len(records) + 1,
        "ts": datetime.now(timezone.utc).isoformat(),
        "ts_unix": round(time.time(), 3),
        "source": source,
        "event": event,
        "prev": prev,
    }
    body["h"] = mac(key, core_of(body))
    return write_record(body)


# --- verification ---------------------------------------------------------
def verify() -> tuple[bool, list[str]]:
    key = load_key()
    records = read_chain()
    problems: list[str] = []

    if not records:
        return True, ["chain is empty (nothing recorded yet)"]

    prev = GENESIS
    for i, rec in enumerate(records, 1):
        if "_corrupt" in rec:
            problems.append(f"record {i}: unparseable JSON (tampered or corrupt)")
            continue
        if rec.get("seq") != i:
            problems.append(f"record {i}: seq is {rec.get('seq')}, expected {i} — records removed or reordered")
        if rec.get("prev") != prev:
            problems.append(f"record {i}: prev hash mismatch — chain broken before this point")
        expected = mac(key, core_of(rec))
        if rec.get("h") != expected:
            problems.append(f"record {i}: HMAC mismatch — record content was modified")
        prev = rec.get("h", prev)

    if ANCHOR.exists():
        try:
            a = json.loads(ANCHOR.read_text())
            if a.get("head") != head_hash(records):
                problems.append(
                    f"ANCHOR MISMATCH: sealed head {a.get('head','')[:16]}… "
                    f"but chain head is {head_hash(records)[:16]}… — "
                    "records were altered or truncated after sealing")
            elif a.get("count") and a["count"] != len(records):
                problems.append(
                    f"ANCHOR COUNT: sealed at {a['count']} records, chain has {len(records)}")
        except Exception as exc:
            problems.append(f"anchor unreadable: {exc}")

    return (not problems), problems


def seal() -> dict:
    key = load_key()
    records = read_chain()
    anchor = {
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "head": head_hash(records),
        "count": len(records),
        "host": os.uname().nodename,
        "kernel": os.uname().release,
        "sig": mac(key, head_hash(records)),
    }
    STORE.mkdir(parents=True, exist_ok=True)
    # 0644, not 0444: the owner must stay able to re-seal on the next timer
    # run. Read-only for everyone else is the point; read-only for us too
    # would silently break re-sealing (PermissionError on the next seal).
    if ANCHOR.exists():
        ANCHOR.chmod(0o644)   # clear a stale 0444 from an earlier run
    ANCHOR.write_text(json.dumps(anchor, indent=2))
    ANCHOR.chmod(0o644)
    return anchor


# --- evidence bundles -----------------------------------------------------
def collect_journal_context(needle_regex: str, window_minutes: int = 10) -> list[str]:
    import subprocess
    out = subprocess.run(
        ["journalctl", "--no-pager", "-q", "-o", "short-iso",
         f"--since=-{window_minutes}min"],
        capture_output=True, text=True, timeout=30,
    )
    if out.returncode != 0:
        return []
    import re
    try:
        pat = re.compile(needle_regex, re.I)
    except re.error:
        return []
    return [l for l in out.stdout.splitlines() if pat.search(l)]


def bundle(event_id: int) -> int:
    import subprocess
    key = load_key()
    records = read_chain()
    rec = next((r for r in records if r.get("seq") == event_id), None)
    if not rec:
        print(f"no event with seq={event_id}", file=sys.stderr)
        return 1

    bdir = STORE / f"bundle-{event_id:06d}"
    bdir.mkdir(parents=True, exist_ok=True)

    # 1. the record itself
    (bdir / "record.json").write_text(json.dumps(rec, indent=2))

    # 2. surrounding journal evidence
    sample = (rec.get("event") or {}).get("sample", "")
    key_terms = [t for t in sample.split() if len(t) > 4][:3]
    ctx = collect_journal_context("|".join(re.escape(t) for t in key_terms)) if key_terms else []
    (bdir / "journal-context.log").write_text("\n".join(ctx) + "\n")

    # 3. system state at collection time
    state = []
    for cmd in (["uname", "-a"], ["uptime"], ["last", "-n", "20"],
                ["ss", "-tulpn"], ["systemctl", "is-active", "firewalld"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            state.append(f"$ {' '.join(cmd)}\n{r.stdout}{r.stderr}")
        except Exception as exc:
            state.append(f"$ {' '.join(cmd)}\n<error: {exc}>")
    (bdir / "system-state.log").write_text("\n\n".join(state) + "\n")

    # 4. full chain so the event's provenance is provable
    (bdir / "chain.jsonl").write_text(CHAIN.read_text() if CHAIN.exists() else "")

    # 5. integrity attestation
    ok, problems = verify()
    manifest = {
        "bundle": bdir.name,
        "event_seq": event_id,
        "created": datetime.now(timezone.utc).isoformat(),
        "chain_intact": ok,
        "chain_problems": problems,
        "record_hmac": rec.get("h"),
        "files": {},
    }
    for f in sorted(bdir.iterdir()):
        if f.name == "manifest.json":
            continue
        manifest["files"][f.name] = hashlib.sha256(f.read_bytes()).hexdigest()

    manifest_text = json.dumps(manifest, indent=2, sort_keys=True)
    manifest["manifest_sig"] = mac(key, manifest_text)
    (bdir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))

    print(f"evidence bundle written: {bdir}")
    print(f"  chain intact: {ok}")
    if problems:
        for p in problems:
            print(f"  ! {p}")
    return 0 if ok else 2


# --- reporting ------------------------------------------------------------
def report(since_hours: int) -> int:
    ok, problems = verify()
    cutoff = time.time() - since_hours * 3600
    records = [r for r in read_chain() if r.get("ts_unix", 0) >= cutoff]

    sev_count = {}
    for r in records:
        # Payload shape is {"severity": <str>, "events": [ {label, count, ...} ]}.
        # Fall back to the event object's own severity if the top-level is absent.
        ev = r.get("event", {})
        top = ev.get("severity")
        items = ev.get("events", []) or []
        for e in items:
            s = e.get("severity") or top or "unknown"
            sev_count[s] = sev_count.get(s, 0) + 1
        if not items and top:
            sev_count[top] = sev_count.get(top, 0) + 1

    print("=" * 72)
    print("  SHIELD KITTY — INCIDENT REPORT")
    print("=" * 72)
    print(f"  generated     : {datetime.now(timezone.utc).isoformat()}")
    print(f"  host          : {os.uname().nodename}")
    print(f"  window        : last {since_hours}h")
    print(f"  events logged : {len(records)}")
    print(f"  chain integrity: {'INTACT' if ok else 'BROKEN'}")
    if problems:
        for p in problems:
            print(f"    ! {p}")
    print()
    if sev_count:
        print("  by severity:")
        for s, c in sorted(sev_count.items(), key=lambda x: -x[1]):
            print(f"    {s:<10} {c}")
        print()
    print("  events:")
    for r in records[-40:]:
        for e in (r.get("event", {}).get("events", []) or []):
            print(f"    [{r['ts']}] {e.get('label')} (x{e.get('count', 1)})")
            if e.get("sample"):
                print(f"        {e['sample'][:96]}")
    print()
    print("  NOTE: this report is evidence of LOGGED ATTEMPTS. It is not proof")
    print("  of a successful compromise. A failed login means the defence held.")
    print("=" * 72)
    return 0


def cmd_list(limit: int) -> int:
    records = read_chain()[-limit:]
    for r in reversed(records):
        if "_corrupt" in r:
            print(f"  {r['_corrupt'][:80]}  <CORRUPT>")
            continue
        labels = ", ".join(
            f"{e.get('label')}(x{e.get('count',1)})"
            for e in (r.get("event", {}).get("events", []) or [])
        ) or str(r.get("event", {}).get("label", ""))
        print(f"  #{r['seq']:<5} {r['ts']}  {labels}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("record")
    p.add_argument("--event", required=True, help="JSON event payload")

    sub.add_parser("verify")
    sub.add_parser("seal")

    p = sub.add_parser("bundle")
    p.add_argument("--id", type=int, required=True)

    p = sub.add_parser("report")
    p.add_argument("--since", type=int, default=24, help="hours")

    p = sub.add_parser("list")
    p.add_argument("-n", type=int, default=20)

    args = ap.parse_args()

    if args.cmd == "record":
        try:
            event = json.loads(args.event)
        except json.JSONDecodeError as exc:
            print(f"invalid JSON: {exc}", file=sys.stderr)
            return 1
        rec = append_event(event)
        print(f"recorded seq={rec['seq']} h={rec['h'][:16]}…")
        return 0

    if args.cmd == "verify":
        ok, problems = verify()
        if ok:
            print("CHAIN INTACT — no evidence of tampering")
        else:
            print("CHAIN BROKEN:")
            for p_ in problems:
                print(f"  ! {p_}")
        return 0 if ok else 2

    if args.cmd == "seal":
        a = seal()
        print(f"sealed: head={a['head'][:16]}… count={a['count']} sig={a['sig'][:16]}…")
        print(f"anchor: {ANCHOR}")
        return 0

    if args.cmd == "bundle":
        return bundle(args.id)

    if args.cmd == "report":
        return report(args.since)

    if args.cmd == "list":
        return cmd_list(args.n)

    return 1


if __name__ == "__main__":
    sys.exit(main())
