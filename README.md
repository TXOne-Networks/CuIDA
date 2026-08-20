# CuIDA

**Recovering hidden Win32 API calls from packed, obfuscated, and position-independent
x86 code — using a symbolic-token attention model instead of unpacking.**

CuIDA is the reference implementation of the research presented at **Black Hat USA 2024**:
*"Attention Is All You Need for Semantics Detection: A Novel Transformer on
Neural-Symbolic Approach"* by Sheng-Hao Ma, Yi-An Lin, and Mars Cheng
([TXOne Networks](https://www.txone.com/)).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](MIT-LICENSE.txt)
[![Black Hat USA 2024](https://img.shields.io/badge/Black%20Hat%20USA-2024-black.svg)](https://i.blackhat.com/BH-US-24/Presentations/REVISED_US24-Ma-Attention-Is-All-You-Need-for-Semantics-Detection-A-Novel-Transformer-on-Neural-Symbolic-Approach-Thursday.pdf)
[![Model: open weights](https://img.shields.io/badge/model-open%20weights%20(307M)-green.svg)](MODEL_CARD.md)

---

## The problem

Modern malware rarely calls Win32 APIs through the import table. It resolves them at
runtime — `GetProcAddress` by hash, a Cobalt Strike-style
`executeWin32api_byHash(0xE553A458, ...)` dispatcher, a commercial packer such as
VMProtect or Themida that virtualizes the whole call. What static analysis and YARA
see is this:

```asm
push 0x40            ; ?
push 0x3000          ; ?
push 0x1000          ; ?
push 0               ; ?
call eax             ; ??? ...unknown pointer
```

The API *name* is hidden. But the **shape of its arguments is not** — argument count,
which slots are NULL, which are stack buffers, which are ANSI vs. wide strings and
roughly how long, which hold flag-like constants. That shape is a fingerprint. A human
reverse engineer reads it in a second: `NULL`, a size, `0x3000` (`MEM_COMMIT | MEM_RESERVE`),
`0x40` (`PAGE_EXECUTE_READWRITE`) is `VirtualAlloc`.

CuIDA learns that same inference. It emulates the binary, abstracts every argument at
every unresolved call site into a symbolic token, and asks an attention model which
Win32 API that argument pattern belongs to — **without unpacking anything**.

```
$ python -c "import lib.attention as A; A.loadModel_lastCheckpoint(); \
             print(A.predictApiList(['NULL','0x00001000','0x00003000','0x00000040']))"

['CreateRectRgn', 'VirtualProtectEx', 'CreateEllipticRgn', 'VirtualProtect', 'VirtualAlloc']
```

## How it works

```
  PE / memory dump / raw shellcode
              |
              v
  [ 1 ] vivisect emulation                        src/lib/scan.py
        - walk every function, emulate it
        - intercept each call to an unresolved pointer
        - force-dump up to 20 stack slots as the callee's arguments
        - recover the real argument count from the stack frame (push counting)
              |
              v
  [ 2 ] symbolic tokenization                     src/lib/scan.py
        raw value  ->  what a human would call it
              |
              v
  [ 3 ] attention model, NumPy only               src/lib/attention.py
        20 argument slots -> 8036-way API classification -> top-5 candidates
              |
              v
  [ 4 ] filter by recovered argument count, report
```

### The symbolic vocabulary

Step 2 is the heart of the method: it throws away everything that is
sample-specific (addresses, pointers, string contents) and keeps only what
generalizes across binaries.

| Token | Meaning |
|---|---|
| `NULL` | zero / null pointer |
| `0x000000nn` | small integer or flag-like constant, kept verbatim |
| `LOCAL_BUFF` | pointer into the current stack frame (an out-parameter) |
| `MEM_BUFF` | pointer to readable memory that is not a string |
| `STR_ANSI_n` / `STR_UNICODE_n` | pointer to an ANSI / wide string, `n` = length bucket |
| `DLL_IMG_PTR` | pointer to a loaded module image |
| `FUNC_RET` | value returned by an earlier, still-unidentified call |
| `RET_OF_FUNCn` | return value of an earlier call that took `n` arguments |

`RET_OF_FUNCn` and `FUNC_RET` are what make this a *use-define chain* analysis rather
than a per-call-site guess: the model sees how the output of one unknown call flows
into the arguments of the next, which is exactly the reasoning a human analyst applies
to a stripped call graph.

### The model

A deliberately small, single-block transformer — **NumPy only, no ML framework, no GPU**.
`src/lib/attention.py` implements the entire forward pass in about 40 lines. Full details
in [MODEL_CARD.md](MODEL_CARD.md).

| | |
|---|---|
| Parameters | 307,012,444 (fp32, 1.23 GB) |
| Vocabulary | 8,036 tokens (1,445 Win32 API names, 6,408 constants, symbolic tokens) |
| Context | 20 argument slots |
| Architecture | single-head causal self-attention, `d_model` 1643, MLP 4x, LayerNorm, flatten, linear classifier |
| Output | 8,036-way classification, reported as top-5 candidates |
| Target | x86 (i386) Windows user-mode code |
| Inference | seconds to load the checkpoint, milliseconds per call site, CPU only |

---

## The three tools

| Tool | Input | What it does |
|---|---|---|
| [`src/nnSymUnpacker.py`](src/nnSymUnpacker.py) | a PE file, a memory dump, or a **live PID** | Recovers the API-level behavior of a packed sample. Given a PID it dumps the running image with PE-Sieve first, so a VMProtect/Themida sample can be read after it unpacks itself in memory — with no unpacker for the protector. |
| [`src/nnYara.py`](src/nnYara.py) | any file + a YARA ruleset | Runs your existing YARA rules twice: once on the raw file, once on the file with CuIDA's predicted API names appended. The difference is the set of behaviors that were hidden behind dynamic dispatch. Existing community rules start matching packed samples, unchanged. |
| [`src/nnShellcode.py`](src/nnShellcode.py) | raw position-independent shellcode | Emulates shellcode that has no PE header and no imports at all, and names the APIs it calls. Ships with a calling-convention template for Cobalt Strike beacons, whose hashed-API dispatcher shifts every argument by one slot. |

---

## Install

```bash
# 1. The checkpoint is stored in Git LFS. Without this you get a 135-byte
#    pointer file instead of the model, and every tool fails at startup.
git lfs install

git clone https://github.com/TXOne-Networks/CuIDA.git
cd CuIDA
git lfs pull                       # ~1.2 GB

# 2. Dependencies
python -m venv .venv
.venv/Scripts/activate             # Windows;  source .venv/bin/activate on Linux/macOS
pip install -r requirements.txt
```

CuIDA finds `model32.cuida` at the repository root, in `src/`, or in `src/lib/`.
To keep the weights elsewhere, set `CUIDA_MODEL=/path/to/model32.cuida`.

### Optional components

`nnYara.py` needs a YARA ruleset. None is vendored here (size and upstream licensing),
so point it at any directory of `.yar` files:

```bash
git clone --depth 1 https://github.com/Yara-Rules/rules src/lib/yara-rules
# or: python src/nnYara.py <file> --rules /path/to/rules
# or: export CUIDA_YARA_RULES=/path/to/rules
```

`nnSymUnpacker.py` needs [PE-Sieve](https://github.com/hasherezade/pe-sieve/releases)
at `src/lib/pe-sieve.exe` **only** to dump a live PID. Scanning a file or an existing
dump works without it.

> **Windows console:** the tools print Unicode via `rich`. On a legacy `cp1252`
> console run `chcp 65001` first, or use Windows Terminal, or set
> `PYTHONUTF8=1`.

---

## Usage

All commands are run from `src/`.

### 1. Recover behavior from a PE or a live process

```bash
cd src
python nnSymUnpacker.py path/to/sample.exe      # a file or a memory dump
python nnSymUnpacker.py 32184                   # a live PID (dumps with PE-Sieve first)
```

Verified against a benign 32-bit system binary, so you can reproduce this without a
malware sample:

```
$ python nnSymUnpacker.py C:/Windows/SysWOW64/winver.exe

[CRITICAL] [v] Exe ImageBase @ 400000
[CRITICAL] [!] found 27 unknown ptr from 59 func calls!
[WARNING]  [FOUND] (4014d3) - WritePrivateProfileStringA, MessageBoxA, SendMessageA
[WARNING]  [FOUND] (4014fc) - CompareStringA, GetDateFormatA, CompareStringW
[WARNING]  [FOUND] (401525) - CreateProcessA
[WARNING]  [FOUND] (401565) - SHGetFolderPathA, InternetOpenW, ModifyMenuW
[WARNING]  [FOUND] (40158b) - CreateEllipticRgn, LoadStringW, GetLocaleInfoW
[WARNING]  [FOUND] (4015cf) - GetLocaleInfoW, SendMessageA, GetDlgItemTextW
[INFO]     [v] total cost 15.97 sec.
```

Each line is a call site whose target was not statically resolvable, followed by
CuIDA's ranked candidates.

### 2. Make existing YARA rules see through dynamic dispatch

```bash
python nnYara.py path/to/sample.exe                       # uses src/lib/yara-rules
python nnYara.py path/to/sample.exe --rules /path/to/rules
python nnYara.py path/to/sample.exe -json                 # machine-readable
```

```json
{
  "sample": "winver.exe",
  "yara_scan":   ["IsPE32", "IsWindowsGUI", "HasRichSignature", "..."],
  "nnyara_scan": ["IsPE32", "IsWindowsGUI", "HasRichSignature", "...",
                  "Str_Win32_Internet_API", "win_private_profile", "HasOverlay"],
  "hidden_ptr_detect": ["Str_Win32_Internet_API", "win_private_profile", "HasOverlay"]
}
```

`hidden_ptr_detect` is the payoff: rules that fire **only** because CuIDA named the
APIs behind the unresolved pointers. Add `-display` for the per-call-site detail.

### 3. Name the APIs in raw shellcode

```bash
python nnShellcode.py path/to/shellcode.bin
```

Reproducible 22-byte example — a Cobalt Strike-style hashed-API call to `VirtualAlloc`
(`NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE`) with the API hash
occupying the first argument slot:

```bash
python -c "open('demo.bin','wb').write(bytes.fromhex('6a4068003000006800100000 6a006858a453e5 ffd0 c3'.replace(' ','')))"
python nnShellcode.py demo.bin
```

```
[DEFAULT] Choose calling convention template of Cabalt Strike
[DEFAULT] Shellcode Base @ 690000
[‼] 690013: CreateRectRgn, SendMessageA, CreateEllipticRgn, VirtualProtect, VirtualAlloc
```

The dispatcher's hash argument is stripped by the calling-convention template in
`nnShellcode.py`, which you can copy and adapt for other loaders.

---

## Repository layout

```
CuIDA/
├── model32.cuida            1.23 GB fp32 checkpoint, i386 model (Git LFS)
├── requirements.txt
├── MODEL_CARD.md            architecture, vocabulary, intended use, limitations
├── SECURITY.md              trust boundaries and safe-handling guidance
├── CONTRIBUTING.md
├── MIT-LICENSE.txt
└── src/
    ├── nnSymUnpacker.py     PE / memory dump / live-PID behavior recovery
    ├── nnYara.py            YARA augmented with predicted API names
    ├── nnShellcode.py       raw position-independent shellcode
    └── lib/
        ├── attention.py     the whole forward pass, NumPy only
        └── scan.py          vivisect emulation and the symbolic tokenizer
```

---

## Evaluation

The Black Hat USA 2024 [slides](https://i.blackhat.com/BH-US-24/Presentations/REVISED_US24-Ma-Attention-Is-All-You-Need-for-Semantics-Detection-A-Novel-Transformer-on-Neural-Symbolic-Approach-Thursday.pdf)
carry the measured results, including the recovery rate on samples protected by
commercial packers (VMProtect, Themida) where no unpacker was used, and the additional
detections obtained by feeding predicted API names to unmodified community YARA rules.

The `winver.exe` and 22-byte shellcode runs above are reproducible on any machine with
this repository checked out, and are the recommended smoke test after installing.

## Limitations

Stated plainly, because they define where the technique is and is not useful:

- **x86 (i386) user-mode only.** The shipped checkpoint is 32-bit. 64-bit binaries are
  detected and skipped. `scan.py` also refuses VB6, Borland, and Delphi binaries, whose
  emulation is unreliable.
- **Top-5 candidates, not ground truth.** Output is a ranked shortlist, narrowed by the
  recovered argument count. APIs with four or more arguments are predicted most reliably;
  one- and two-argument APIs are frequently ambiguous by construction, because their
  argument shapes are genuinely indistinguishable.
- **Emulation-bound.** Anything vivisect cannot emulate or reach is invisible to CuIDA.
  Coverage, not the model, is usually the limiting factor.
- **The checkpoint is a Python pickle.** Loading it executes code. Load only the
  weights you obtained from this repository — see [SECURITY.md](SECURITY.md). Migrating
  to a safe format is on the roadmap below.
- **Training corpus and training code are not part of this release.** The methodology
  is documented in the talk; this repository ships inference and the tooling built on it.

## Roadmap

Contributions in any of these directions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

- **Safe checkpoint format.** Ship the weights as `safetensors` so loading involves no
  code execution, and keep the vocabulary as plain JSON alongside it.
- **x64 model.** The pipeline is architecture-agnostic; `scan.py` already handles the
  `msx64call` convention. What is missing is a 64-bit checkpoint.
- **Disassembler integration.** Expose predictions as an IDA / Ghidra / Binary Ninja
  plugin that renames call sites in place.
- **Calling-convention templates.** `nnShellcode.py` ships one for Cobalt Strike; other
  loaders and hashed-API dispatchers need their own.
- **Evaluation harness.** A public, reproducible benchmark over labelled samples, so
  changes to the tokenizer or the model can be measured rather than eyeballed.

## Research

- **Talk:** *Attention Is All You Need for Semantics Detection: A Novel Transformer on
  Neural-Symbolic Approach* — Black Hat USA 2024, Briefings.
- **Authors:** Sheng-Hao Ma ([@aaaddress1](https://github.com/aaaddress1)), Yi-An Lin,
  Mars Cheng — TXOne Networks.
- **Slides:** [PDF](https://i.blackhat.com/BH-US-24/Presentations/REVISED_US24-Ma-Attention-Is-All-You-Need-for-Semantics-Detection-A-Novel-Transformer-on-Neural-Symbolic-Approach-Thursday.pdf)

```bibtex
@misc{ma2024cuida,
  title  = {Attention Is All You Need for Semantics Detection:
            A Novel Transformer on Neural-Symbolic Approach},
  author = {Ma, Sheng-Hao and Lin, Yi-An and Cheng, Mars},
  year   = {2024},
  note   = {Black Hat USA 2024 Briefings. Reference implementation:
            https://github.com/TXOne-Networks/CuIDA}
}
```

## Acknowledgements

CuIDA stands on other people's open work:
[vivisect](https://github.com/vivisect/vivisect) for emulation and its import API
database, [viv_utils](https://github.com/mandiant/viv_utils) for workspace handling,
[PE-Sieve](https://github.com/hasherezade/pe-sieve) by
[@hasherezade](https://github.com/hasherezade) for in-memory image dumping,
[YARA](https://virustotal.github.io/yara/), and the community rule authors whose
signatures `nnYara.py` amplifies.

## License

MIT — see [MIT-LICENSE.txt](MIT-LICENSE.txt). The model weights are released under the
same terms.
