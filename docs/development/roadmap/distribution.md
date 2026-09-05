# Distribution: getting Glaurung installable

> **Kind:** plan · **Status:** proposed

Every number here was measured on 2026-09-04 and the command that produced it
is written next to it. The `uvx` timing and the 101-package install are at
`80f5d106`, which is the commit that `git+https://…` resolved to at the time;
everything else is at `e78d8080`. Nothing in this document authorizes a
release; it records what a release would cost and what stands in the way.

## The problem, stated

`glaurung.dev` tells a newcomer to run:

```console
$ uvx --from git+https://github.com/mjbommar/glaurung.git glaurung kickoff /bin/ls
```

That is a **source build**. Measured cold, with a fresh `UV_CACHE_DIR`, on this
24-core development host:

```console
$ UV_CACHE_DIR=$PWD/cache /usr/bin/time -v uvx --from git+https://github.com/mjbommar/glaurung.git glaurung --version
glaurung 0.1.0
Elapsed (wall clock) time: 2:08.29
Percent of CPU this job got: 349%
Maximum resident set size: 3,749,956 kB
```

It works, but it costs a Rust toolchain, roughly two minutes on 24 cores (more
like ten on a laptop), and **3.7 GB of peak RSS** — which is what kills it on a
4 GB VM or a small CI runner, and it fails there as an OOM rather than as
anything legible.

Against that, a published wheel is one download:

```console
$ cp target/release/libglaurung.so /tmp/x.so && strip /tmp/x.so && stat -c%s /tmp/x.so
45009296
$ python3 -c "import zlib; print(len(zlib.compress(open('/tmp/x.so','rb').read(), 6)))"
8374758
```

A wheel is a zip, so deflate level 6 is the right estimate: **8.37 MB, no
toolchain, seconds.** The 48 MB unstripped `.so` is 25 MB of `.rodata`
(capstone, iced-x86 and whatlang tables) and compresses well. Size is not the
blocker.

## What already exists and has never run

`.github/workflows/CI.yml` is maturin's generated release matrix: six Linux
targets, four musllinux, two Windows, two macOS, an sdist, and a `release` job
with build-provenance attestation and `maturin upload`, all gated on
`refs/tags/*`. Someone did the work.

It has never fired:

```console
$ git tag | grep -v decbench | grep -v premerge     # nothing
$ curl -s -o /dev/null -w '%{http_code}' https://pypi.org/pypi/glaurung/json
404
```

The name is unclaimed.

## The dependency tax

`glaurung --version` installs **101 packages** (uv's own count during the run
above). Resolved separately:

```console
$ uv lock          # with the current [project.dependencies]
104 packages
$ uv lock          # with only structlog, pydantic, rich, PyYAML
12 packages
```

The difference is `pydantic-ai` and `pydantic-ai-slim[anthropic,google,openai]`
pulling anthropic, openai, google-genai, cryptography, tiktoken, fastmcp-slim,
authlib and the rest. They are not needed by the analysis path:

```console
$ grep -rl '^\s*\(import\|from\) pydantic_ai\b' python/glaurung --include=*.py | grep -v /llm/ | wc -l
0
$ grep -rl '^\s*\(import\|from\) dotenv\b'     python/glaurung --include=*.py | grep -v /llm/ | wc -l
0
```

`pydantic` itself has exactly one non-`llm/` consumer
(`python/glaurung/java_classfile_policy.py`), so it stays in the base.

The runtime side is already lazy enough for the split — `python/glaurung/cli/main.py`
loads one command per invocation, pinned by `python/tests/test_cli_startup_is_lazy.py`:

```console
$ python -c "import time,sys; t=time.perf_counter(); import glaurung.cli; \
    print(f'{(time.perf_counter()-t)*1000:.0f} ms', len(sys.modules), 'pydantic_ai' in sys.modules)"
48 ms 138 False
```

## The plan, in order

1. **Tag a release.** The matrix and the upload job exist; the gap is a tag and
   the `PYPI_API_TOKEN` secret. This is the whole difference between "install
   Rust and wait" and `uvx glaurung`.
2. **Move the LLM stack to an extra.** `pydantic-ai`, `pydantic-ai-slim[...]`
   and `python-dotenv` into `[project.optional-dependencies] llm`. Base install
   goes 104 → 12 packages; `uvx --from 'glaurung[llm]' glaurung ask` keeps the
   agent path. Needs a legible error from `glaurung ask` when the extra is
   absent — `pip install 'glaurung[llm]'`, not an `ImportError` traceback.
3. **Add `pyo3/abi3-py312`.** One wheel per platform instead of one per platform
   per Python, and Python 3.15 installs on release day without a rebuild.
   Type-checks clean today:

   ```console
   $ cargo check --features python-ext,pyo3/abi3-py312
   Finished `dev` profile in 45.89s     # exit 0, 28 pre-existing warnings
   ```

   **Confirm with a real `maturin build --release`, not that check** — abi3 also
   has to link against the limited API, and `cargo check` never links.
4. **Add `[project.urls]`.** `pyproject.toml` has none, so a published PyPI page
   would have no route back to `glaurung.dev` or the repository. Since PyPI will
   rank for the name, this is the most direct version of "bring people to
   Glaurung".
5. **Switch to Trusted Publishing.** The release job already requests
   `id-token: write` for attestation, so the OIDC publisher is nearly free and
   removes a long-lived token.
6. **Then update `glaurung.dev`.** Three panes carry the `git+` form —
   `src/pages/index.astro:76`, `src/pages/docs.astro:19,22`, and
   `src/pages/llms.txt.ts:39` — plus a `uv run --with 'glaurung @ git+…'`
   example. Keep the git form on the contributor page.

## Open question

**What a machine with no Rust at all actually does is untested.** An attempt to
check it by removing `cargo` from `PATH` proved nothing: maturin found
`~/.cargo/bin` and built anyway. Answering it needs a clean container. It does
not change the ordering above — a published wheel makes the question moot — but
it should not be asserted either way until someone runs it.

## Not in scope

Extracting the C front end and the metrics into a separately published crate was
considered and rejected on 2026-09-04. The cut is unusually clean — outside
`src/csource/{lower,equiv}` the three trees reach nothing else in the crate, and
their only third-party dependencies are `regex`, `once_cell` and `capstone` —
but the goal is to bring people *to* Glaurung, and a second package divides the
audience rather than growing it. The analysis is preserved here so the option
can be reopened deliberately rather than rediscovered.

## Related

* [source metrics](../../reference/source-metrics.md) — the capability that most
  benefits from being one `pip install` away
* [setup.md](../setup.md) — the source-build path this plan does not replace
