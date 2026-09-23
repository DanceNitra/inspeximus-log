#!/usr/bin/env python
"""Check that the current log continues the frozen first one, from the published files alone.

The first log, origin 92.5.74.17.sslip.io/log, was frozen at 10 entries on 2026-09-23. The current
log, origin dancenitra.github.io/inspeximus-log, carries the first log's last signed checkpoint in
its entry 0, inside the registration policy's notes. Entry 0 is under every root the current log
will ever sign, so the handover cannot be changed later without changing the current log.

This passes only if all of the following hold, and the first failure exits 1 with the reason:

  1. The first log's published checkpoint verifies under the FIRST log's pinned key.
  2. Entry 0 of the current log is a registration policy whose notes are a succession record.
  3. The checkpoint in that record is byte-identical to the first log's published checkpoint, and it
     verifies under the same pinned key. So the current log names exactly the head that was frozen.
  4. The record's size and root match the first log's published head.
  5. Entry 0's leaf hashes to the leaf hash the current log publishes for it, and its inclusion proof
     folds to the root in the current log's checkpoint, which verifies under the CURRENT log's key.

It needs no server. Point it at the Pages copy or at a directory:

    python verify_succession.py --first https://dancenitra.github.io/inspeximus-log/log \\
        --current https://dancenitra.github.io/inspeximus-log \\
        --first-vkey trust/checkpoint.vkey --current-vkey trust/checkpoint-v2.vkey
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import ssl
import sys
import urllib.request

from inspeximus import merkle
from inspeximus.checkpoint import parse_checkpoint
# Imported here, not inside a try: a missing library must stop the run as an error, never
# read as a signature that failed to verify.
from cryptography.exceptions import InvalidSignature

try:
    import certifi
    CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:                                                    # noqa: BLE001
    CTX = ssl.create_default_context()


def reader(base: str):
    """name -> bytes, from a URL prefix or a local directory."""
    if base.startswith(("http://", "https://")):
        def get(name):
            req = urllib.request.Request(base.rstrip("/") + "/" + name,
                                         headers={"User-Agent": "inspeximus-succession-check"})
            with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
                return r.read()
        return get
    return lambda name: open(os.path.join(base, name), "rb").read()


def read_vkey(path: str):
    name, _kid, blob = open(path, encoding="utf-8").read().strip().split("+", 2)
    raw = base64.b64decode(blob)
    if raw[0] != 0x01 or len(raw) != 33:
        raise ValueError("%s is not an Ed25519 vkey" % path)
    return name, raw[1:].hex()


def fail(reason: str) -> int:
    print("REFUSED: " + reason)
    return 1


def check(first, current, first_vkey, current_vkey) -> int:
    fname, fpub = first_vkey
    cname, cpub = current_vkey

    first_note = first("checkpoint").decode("utf-8")
    try:
        fcp = parse_checkpoint(first_note, {fname: fpub}, required=[fname])
    except (ValueError, InvalidSignature) as e:
        return fail("the first log's checkpoint does not verify under its pinned key: %s %s"
                    % (type(e).__name__, e))
    fhead = json.loads(first("head.json"))

    rows = [json.loads(ln) for ln in current("log.jsonl").decode("utf-8").splitlines() if ln.strip()]
    if not rows or rows[0].get("index") != 0:
        return fail("the current log publishes no entry 0")
    leaf = current(rows[0]["leaf"])
    entry = json.loads(leaf)
    if entry.get("kind") != "registration-policy":
        return fail("entry 0 of the current log is %r, not a registration policy" % entry.get("kind"))
    try:
        record = json.loads(entry["policy"]["notes"])
    except Exception:                                                  # noqa: BLE001
        return fail("entry 0's policy notes are not a succession record")
    if record.get("kind") != "inspeximus.log-succession/1":
        return fail("entry 0's notes are %r, not a succession record" % record.get("kind"))

    named = record.get("predecessor_checkpoint", "")
    if named != first_note:
        return fail("entry 0 names a predecessor checkpoint that is not the first log's published "
                    "checkpoint (%d vs %d bytes)" % (len(named), len(first_note)))
    try:
        parse_checkpoint(named, {fname: fpub}, required=[fname])
    except (ValueError, InvalidSignature) as e:
        return fail("the checkpoint entry 0 names does not verify under the first log's key: %s %s"
                    % (type(e).__name__, e))
    if (record.get("predecessor_size"), record.get("predecessor_root")) != \
            (fhead.get("n_writes"), fhead.get("writes_tip")) or fcp["size"] != fhead.get("n_writes"):
        return fail("the succession record's size and root do not match the first log's head")

    if hashlib.sha256(b"\x00" + leaf).hexdigest() != rows[0]["leaf_hash"]:
        return fail("entry 0's leaf does not hash to the leaf hash the current log publishes")
    try:
        ccp = parse_checkpoint(current("checkpoint").decode("utf-8"), {cname: cpub}, required=[cname])
    except (ValueError, InvalidSignature) as e:
        return fail("the current log's checkpoint does not verify under its pinned key: %s %s"
                    % (type(e).__name__, e))
    proof = json.loads(current(rows[0]["proof"]))
    if proof["tree_size"] != ccp["size"] or not merkle.verify_inclusion(
            leaf, 0, proof["tree_size"], [bytes.fromhex(h) for h in proof["audit_path"]], ccp["root"]):
        return fail("entry 0 is not included under the current log's signed root")

    print("OK: %s (%d entries, root %s...) continues %s frozen at %d entries, root %s..."
          % (cname, ccp["size"], ccp["root"].hex()[:16], fname, fcp["size"], fcp["root"].hex()[:16]))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--first", required=True, help="the frozen first log: URL or directory")
    ap.add_argument("--current", required=True, help="the current log: URL or directory")
    ap.add_argument("--first-vkey", default="trust/checkpoint.vkey")
    ap.add_argument("--current-vkey", default="trust/checkpoint-v2.vkey")
    a = ap.parse_args(argv)
    return check(reader(a.first), reader(a.current), read_vkey(a.first_vkey), read_vkey(a.current_vkey))


if __name__ == "__main__":
    sys.exit(main())
