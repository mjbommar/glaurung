# Real-world Windows PE corpus

This directory vendors a real-world Windows PE smoke and stress corpus
for Glaurung parser and triage development. The files were selected from
the Windows corpus roots reviewed during the windows-port work:

- `/nas4/data/binary-analysis/glaurung/binaries/windows-10-x64/`
- `/nas4/data/binary-analysis/glaurung/binaries/windows-11-x64/`
- `/nas4/data/binary-analysis/glaurung/binaries/windows-8-pro-x64/`
- `/nas4/data/binary-analysis/glaurung/binaries/windows-update/`
- `/nas4/data/binary-analysis/windows-drivers.sqfs`, mounted at
  `/mnt/windows-drivers-sqfs/`

Selection began as a deterministic-random sample with seed
`glaurung-windows-vendor-2026-05-19-v2`, constrained to 10 small files.
The corpus was then expanded with seed
`glaurung-windows-vendor-2026-05-19-v3` to add 20 non-duplicate,
high-volume Windows system and Windows Update vendor DLL/SYS/EXE
targets.

See `MANIFEST.json` for hashes, original source paths, and file
descriptions. These are third-party Windows binaries copied for local
parser/regression testing; review redistribution constraints before
publishing them outside this repository/workspace.
