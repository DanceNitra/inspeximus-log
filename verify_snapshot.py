#!/usr/bin/env python
"""Refuse to publish a snapshot of the log unless it verifies against the pinned key and extends
the history already published.

The host pushes its static files to the `incoming` branch. It cannot publish them: only the
workflow on `main` deploys Pages, and it runs this first. A snapshot is published only if all of
the following hold, and the first failure exits 1 with the reason:

  1. The checkpoint is a signed note from the key pinned in `trust/checkpoint.vkey` on `main`.
     The key is never read from the snapshot, because the host wrote the snapshot.
  2. The checkpoint's tree size and root equal the head's `n_writes` and `writes_tip`.
  3. The root recomputed from the leaf hashes in `log.jsonl` equals that root, and `sth_hash`
     follows from the head's own fields.
  4. Every leaf file hashes to the leaf hash `log.jsonl` names for it, and every inclusion proof
     folds that leaf to the same root.
  5. The history extends the head that is live on Pages now: the first `n` leaves of the new log
     reproduce the root published before. A shorter log is a ROLLBACK and a different root is a
     FORK.

What it does NOT check: that an entry is true, or that nobody was shown a different history.
Only an independent witness answers the second.

    python verify_snapshot.py --snapshot incoming/log --vkey trust/checkpoint.vkey \\
        --previous https://dancenitra.github.io/inspeximus-log/log
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

from inspeximus import merkle
from inspeximus.checkpoint import parse_checkpoint
from inspeximus.witness_log import judge


def fail(reason: str) -> int:
    print("REFUSED: " + reason)
    return 1


def read_vkey(path: str):
    name, _kid, blob = open(path, encoding="utf-8").read().strip().split("+", 2)
    raw = base64.b64decode(blob)
    if raw[0] != 0x01 or len(raw) != 33:
        raise ValueError("the pinned vkey is not an Ed25519 key")
    return name, raw[1:].hex()


def previous_head(url: str, baseline: str):
    """The head live on Pages now, or the committed baseline before the first deploy."""
    try:
        req = urllib.request.Request(url.rstrip("/") + "/head.json",
                                     headers={"User-Agent": "inspeximus-log-mirror"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8")), "live Pages"
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
    with open(baseline, encoding="utf-8") as fh:
        return json.load(fh), "baseline " + os.path.basename(baseline)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--snapshot", required=True, help="the directory the host pushed")
    ap.add_argument("--vkey", required=True, help="the pinned key, from main")
    ap.add_argument("--expect-key", default="", help="the key's hex, a second copy to compare")
    ap.add_argument("--previous", default="", help="the Pages URL of the log published now")
    ap.add_argument("--baseline", default="trust/baseline-head.json")
    a = ap.parse_args(argv)

    name, pub = read_vkey(a.vkey)
    if a.expect_key and pub != a.expect_key:
        return fail("the pinned vkey holds %s..., the workflow expects %s..."
                    % (pub[:16], a.expect_key[:16]))

    snap = a.snapshot
    try:
        note = open(os.path.join(snap, "checkpoint"), encoding="utf-8").read()
        cp = parse_checkpoint(note, {name: pub}, required=[name])
    except Exception as e:                                             # noqa: BLE001
        # InvalidSignature carries no message, so name the exception rather than print nothing.
        return fail("the checkpoint does not verify under the pinned key: %s %s"
                    % (type(e).__name__, e))
    if cp["origin"] != name:
        return fail("the checkpoint names origin %r, the pinned key is for %r" % (cp["origin"], name))

    head = json.load(open(os.path.join(snap, "head.json"), encoding="utf-8"))
    if cp["size"] != head.get("n_writes") or cp["root"].hex() != head.get("writes_tip"):
        return fail("the signed checkpoint (%d, %s...) and head.json (%s, %s...) disagree"
                    % (cp["size"], cp["root"].hex()[:16], head.get("n_writes"),
                       str(head.get("writes_tip"))[:16]))

    rows = [json.loads(line) for line in
            open(os.path.join(snap, "log.jsonl"), encoding="utf-8").read().splitlines()
            if line.strip()]
    mtl = [bytes.fromhex(r["leaf_hash"]) for r in rows]
    root = cp["root"]

    for r in rows:
        leaf = open(os.path.join(snap, r["leaf"]), "rb").read()
        if hashlib.sha256(b"\x00" + leaf).hexdigest() != r["leaf_hash"]:
            return fail("entry %d: the leaf file does not hash to its leaf hash" % r["index"])
        proof = json.load(open(os.path.join(snap, r["proof"]), encoding="utf-8"))
        if proof["tree_size"] != cp["size"] or proof["root"] != root.hex():
            return fail("entry %d: the proof is for tree %s, the checkpoint is for %d"
                        % (r["index"], proof["tree_size"], cp["size"]))
        if not merkle.verify_inclusion(leaf, proof["index"], proof["tree_size"],
                                       [bytes.fromhex(h) for h in proof["audit_path"]], root):
            return fail("entry %d: the inclusion proof does not reach the root" % r["index"])

    prev, source = (None, "none")
    if a.previous:
        prev, source = previous_head(a.previous, a.baseline)
    verdict, reason = judge(head, mtl, prev)
    if verdict not in ("EXTENDS", "FIRST_CONTACT"):
        return fail("%s against %s: %s" % (verdict, source, reason))
    if verdict == "FIRST_CONTACT" and a.previous:
        return fail("no previous head to compare against, and a mirror must never start blind")

    print("OK: checkpoint signed by %s, %d entries, root %s, %s against %s"
          % (name, cp["size"], root.hex(), verdict, source))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
