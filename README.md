# inspeximus-log

A verified mirror of the inspeximus hosted transparency log, served by GitHub Pages.

| log | origin | where | state |
|---|---|---|---|
| current | `dancenitra.github.io/inspeximus-log` | https://dancenitra.github.io/inspeximus-log/ | grows |
| first | `92.5.74.17.sslip.io/log` | https://dancenitra.github.io/inspeximus-log/log/ | frozen at 10 entries on 2026-09-23 |

Both are signed by one Ed25519 key:
`9fb780dd72894867c6dac8e140cc78d755617147d20cfd26bfe557190f65ac49`.

The current log's entry 0 is a registration policy whose notes carry the first log's last signed
checkpoint. Entry 0 is under every root the current log signs, so the handover is part of its
history. `verify_succession.py` checks it from the published files, with no server:

```bash
pip install inspeximus==3.7.0 cryptography
python verify_succession.py --first https://dancenitra.github.io/inspeximus-log/log \
    --current https://dancenitra.github.io/inspeximus-log
```

The log host pushes its static files to the `incoming` branch and cannot publish them. The
`publish` workflow on `main` publishes a snapshot only if the first log matches
`trust/frozen-v1.sha256` byte for byte, the current log verifies against `trust/checkpoint-v2.vkey`
and extends the head that is live on Pages, and `verify_succession.py` passes. If a check fails,
nothing is published and the run ends red.
