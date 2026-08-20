# Security

CuIDA is a malware-analysis tool. It is normally pointed at hostile input, so the trust
boundaries are worth stating explicitly.

## Handling samples

**Analyse in a disposable VM, with no network.** Two of the three tools never execute the
sample — `nnYara.py` and `nnSymUnpacker.py` (file mode) emulate it inside vivisect, and
`nnShellcode.py` emulates raw shellcode. Emulation is not a sandbox, however: it parses
attacker-controlled structures with a large amount of Python and native code, and a
malformed PE aimed at vivisect or `pefile` is a plausible attack surface.

**One mode does run the sample: `nnSymUnpacker.py <PID>`.** Dumping a live process means
that process is already running on your machine, by your choice. That mode exists because
it is how you read a VMProtect/Themida sample after it has unpacked itself in memory, and
it belongs in an isolated VM only.

## The checkpoint is a Python pickle

`model32.cuida` is loaded with `pickle.load`, which **executes code contained in the
file**. Consequences:

- Load only the checkpoint you obtained from this repository over Git LFS. Do not load a
  `.cuida` file someone sent you, and do not accept one from an untrusted mirror.
- If you distribute a modified checkpoint, distribute a hash with it.
- Replacing this format with `safetensors` is on the [roadmap](README.md#roadmap) and is
  the single highest-value security contribution to the project.

## Third-party YARA rules

`nnYara.py` compiles every `.yar` file it finds under the ruleset directory you point it
at. YARA rules are code; a ruleset can read files via `include` and consume large amounts
of memory. Use rulesets you trust, from a source you chose deliberately. Rules that fail
to compile are counted and skipped, not silently ignored.

## What the tools write to disk

- `scanlog.txt` in the working directory (debug log).
- `src/lib/process_<pid>/` — PE-Sieve dumps, when using live-PID mode. These are copies
  of live malware images. They are deleted at the start of the next PID scan, but not on
  exit; clean them up yourself.

## Reporting a vulnerability

Please report security issues in CuIDA itself — not in the samples it analyses — through
**GitHub private vulnerability reporting** on
[TXOne-Networks/CuIDA](https://github.com/TXOne-Networks/CuIDA/security/advisories/new),
rather than in a public issue.

Please include the input that triggers the problem, the versions of `vivisect`,
`viv_utils`, and Python you used, and the full traceback. If a proof-of-concept sample is
malicious, describe it rather than attaching it.

This is a research tool released as-is under the MIT licence; there is no commercial
support commitment attached to it.
