# inspeximus-log

A verified mirror of the inspeximus hosted transparency log, served by GitHub Pages at
https://dancenitra.github.io/inspeximus-log/log/.

The log host pushes its static files to the `incoming` branch. It cannot publish them. The
`publish` workflow on `main` runs `verify_snapshot.py` first, and publishes only a snapshot whose
checkpoint is signed by the key in `trust/checkpoint.vkey` and whose history extends the head that
is live on Pages. If a check fails, nothing is published and the run ends red.

Verification key (Ed25519): `9fb780dd72894867c6dac8e140cc78d755617147d20cfd26bfe557190f65ac49`
