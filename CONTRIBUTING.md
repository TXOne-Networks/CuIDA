# Contributing to CuIDA

CuIDA is the reference implementation of a Black Hat USA 2024 research result, published
so that other people can use it, check it, and build on it. Contributions are welcome —
particularly the ones listed under [Roadmap](README.md#roadmap).

## Setup

```bash
git lfs install
git clone https://github.com/TXOne-Networks/CuIDA.git
cd CuIDA
git lfs pull
python -m venv .venv && .venv/Scripts/activate     # or: source .venv/bin/activate
pip install -r requirements.txt
```

## Smoke test

Before and after any change, run both of these. Neither needs a malware sample, and
together they exercise emulation, tokenization, inference, and the argument-count filter.

```bash
cd src

# 1. a benign 32-bit PE: expect "found N unknown ptr from M func calls" and [FOUND] lines
python nnSymUnpacker.py C:/Windows/SysWOW64/winver.exe

# 2. a 22-byte Cobalt Strike-style hashed-API call: expect VirtualAlloc in the candidates
python -c "open('demo.bin','wb').write(bytes.fromhex('6a40680030000068001000006a006858a453e5ffd0c3'))"
python nnShellcode.py demo.bin
```

If you have a YARA ruleset installed, also run
`python nnYara.py C:/Windows/SysWOW64/winver.exe --rules <dir> -json` and check that
`hidden_ptr_detect` is non-empty.

## Where help is most useful

| Area | Why it matters |
|---|---|
| **`safetensors` checkpoint** | Removes pickle code execution and makes the weights loadable from any language. See [SECURITY.md](SECURITY.md). |
| **Evaluation harness** | There is no public benchmark. Without one, tokenizer and model changes cannot be measured, only argued about. This is the highest-value contribution. |
| **x64 checkpoint** | `scan.py` already handles `msx64call`; the 64-bit model is what is missing. |
| **Calling-convention templates** | `nnShellcode.py` ships one for Cobalt Strike. Other loaders shift arguments differently and each needs a small template. |
| **Disassembler plugins** | Feeding predictions back into IDA / Ghidra / Binary Ninja as renamed call sites. |
| **Smaller model** | 86% of the parameters are in the classifier head. Weight tying or a low-rank head should cut the checkpoint dramatically. |

## Code conventions

Match the surrounding code rather than a style guide: the existing source uses
`camelCase` for functions and locals, keeps comments short and practical, and links to
the upstream vivisect source whenever it re-implements or monkey-patches part of it.
Please keep those upstream `# ref:` links up to date when you touch that code — they are
what make the emulator patches reviewable.

Two things to be careful about:

- **`vivisect` and `viv_utils` are pinned** in `requirements.txt` because `scan.py`
  patches vivisect internals. If a change requires a newer version, say so in the pull
  request and re-run the smoke test.
- **The symbolic vocabulary is part of the model contract.** Adding or renaming a token in
  `scan.py` (`symbolic_present`, `data_reprsent`) silently changes what the model sees;
  unknown tokens collapse to `MEM_BUFF` at inference. Tokenizer changes need a matching
  checkpoint.

## Pull requests

Describe what you changed and what you ran. If the change affects analysis output, include
the before/after for at least one of the smoke tests above. Contributions are accepted
under the repository's [MIT licence](MIT-LICENSE.txt).
