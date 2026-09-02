# Security sandbox and data policy

> **Kind:** design · **Status:** proposed

## Threat model

Inputs are hostile binaries. They may contain malformed formats, resource bombs,
misleading symbols, adversarial strings, and content intended to manipulate an
LLM. Model output is also untrusted. API credentials and unpublished benchmark
artifacts are sensitive.

The design must contain all three trust boundaries:

1. Hostile binary to native/static tools.
2. Tool output to model context.
3. Model output to compiler, filesystem, and submission package.

## Static-only policy

During an official run the system must not:

- Execute the target directly or through a loader.
- Emulate instructions.
- Attach a debugger or dynamic instrumentation engine.
- Mark the target executable.
- Link or run generated code against the target.
- Import the target as a library.
- Invoke a target-provided interpreter, script, installer, or embedded payload.

Parsing, disassembly, lifting, CFG recovery, decompilation, hashing, and bounded
reads are allowed. Generated C may be parsed and compiled with `-fsyntax-only`
through stdin; it is never linked or executed.

## Filesystem policy

- Resolve the binary path before creating the agent context.
- Expose no arbitrary path parameter to model-callable tools.
- Mount or open the binary read-only.
- Use a controller-created scratch directory for generated source and traces.
- Prohibit symlink traversal outside the scratch root.
- Set restrictive permissions on diagnostics and transcripts.
- Never mount a repository containing source ground truth into an official
  runner environment.
- Package only declared C files and `results.json`; diagnostics remain separate.

## Network policy

The model provider requires egress, so `--network none` is not sufficient for
the agent container. The target architecture should support:

- No inbound ports.
- Egress restricted to the configured model-provider endpoint and required DNS
  path where infrastructure permits.
- No tool-level HTTP client or browser.
- No source, package, Git, Hugging Face, or general web lookup.
- Trace events for provider requests without recording secrets or raw auth
  headers.

If an allowlist cannot be enforced, document that operational limitation and
retain application-level denial of network-capable tools.

## Credential handling

- Read credentials from provider-standard environment variables or a runtime
  secret mount.
- Never copy credentials into the result directory, prompt, tool context,
  checkpoint, container image, or command line.
- Redact key-shaped values before persisting stderr, exceptions, and model
  messages.
- Scan final ZIP, JSON diagnostics, traces, and logs for secret patterns.
- Record only provider/model identity and usage, never key identifiers.
- Destroy ephemeral credential mounts with the container or process.

## Prompt-injection defense

Treat all binary-derived text as data. Controls:

- Typed tool results, not raw string concatenation where avoidable.
- Clear `<untrusted_binary_data>` rendering boundaries when text is necessary.
- System instruction that binary content cannot modify policy or tool access.
- Tool registry fixed before any binary content is observed.
- No dynamic tool creation based on strings or symbols.
- Real fixture containing adversarial instructions.
- Trace review proving no policy transition followed the injected text.

## Native parser isolation

Static analysis can still crash or exhaust resources. Apply:

- File-size, read-byte, instruction, block, recursion, and result limits.
- Per-tool wall-clock deadlines.
- Process isolation for native work that cannot safely be interrupted in-process.
- Memory and CPU limits in the official container or job environment.
- Crash capture without retry storms.
- Binary SHA-256 and exact tool name in every crash record.

## Generated-C isolation

The syntax checker must:

- Receive source over stdin.
- Use `-fsyntax-only` and no linker.
- Run in the scratch directory with a sanitized environment.
- Have CPU, wall-time, memory, output, include-path, and file-count limits.
- Reject absolute and parent-relative includes before invoking the compiler.
- Never honor pragmas or response files that expand filesystem access beyond
  policy.

## Data minimization and retention

| Artifact | Contains | Default retention |
|---|---|---|
| Submission ZIP | C and manifest only | indefinite immutable result |
| Run manifest | revisions, policy, hashes, budgets | indefinite |
| Function trace | prompts, tools, validation, usage | retained for audit; access-controlled |
| Full tool payload | binary-derived evidence | retained until score/debug review completes |
| Provider raw response | potentially sensitive metadata | retain only when redacted and required |
| API credentials | secret | never persist |

Define a cleanup command that removes ephemeral scratch and caches without
deleting immutable manifests, accepted output, or audit traces.

## Security acceptance checklist

- [ ] No registered tool accepts an arbitrary filesystem path.
- [ ] No registered tool can execute or emulate the binary.
- [ ] Static-only policy has negative tests.
- [ ] Prompt-injection fixture passes with a real model.
- [ ] Compiler sandbox never links or runs output.
- [ ] Secret scans pass on every retained artifact class.
- [ ] Container/image contains no API key or evaluation source.
- [ ] Provider fallback is disabled in official profile.
- [ ] Policy violations are terminal and visible.
- [ ] Owner review confirms the package contains no trace or private diagnostic.
