# Model card — `model32.cuida`

The open-weights model behind [CuIDA](README.md). Everything below was read directly
out of the shipped checkpoint, so it describes what you actually get.

| | |
|---|---|
| File | `model32.cuida` (repository root, Git LFS) |
| Size | 1,228,254,478 bytes |
| Parameters | 307,012,444, all `float32` |
| Format | Python pickle — see [Checkpoint format](#checkpoint-format) and [SECURITY.md](SECURITY.md) |
| Target | x86 (i386) Windows user-mode code |
| Runtime | NumPy on CPU; no ML framework, no GPU, no network |
| License | MIT, same as the code |

## What it does

Given the **symbolic shape of the arguments** at an unresolved call site, it predicts
**which Win32 API is being called**. It never sees instruction bytes, opcodes, addresses,
or string contents — only a sequence of up to 20 abstract argument tokens produced by
`src/lib/scan.py`.

- **Input:** up to 20 tokens, e.g. `["NULL", "0x00001000", "0x00003000", "0x00000040"]`
- **Output:** a probability distribution over the full 8,036-token vocabulary; callers
  take the top-5 (`src/lib/attention.py:predictApiList`)
- **Downstream filter:** candidates are then narrowed by the argument count recovered
  from the stack frame, which is where most of the false positives are removed

### Intended use

Reverse engineering, malware triage, and detection engineering on x86 Windows binaries:
naming dynamically resolved APIs in packed samples, in memory dumps, and in raw
shellcode, and enriching YARA rules with behaviors that dynamic dispatch hides.

### Out of scope

- **Not a classifier of malice.** It names APIs; it does not decide whether a sample is
  malicious. Nothing in the output should be treated as a verdict.
- **Not ground truth.** The output is a ranked shortlist. One- and two-argument APIs are
  often genuinely indistinguishable from their argument shape alone, and the model will
  return plausible siblings (`VirtualAlloc` / `VirtualProtect` / `CreateRectRgn` all take
  four integer-ish arguments).
- **Not for 64-bit code.** This checkpoint is 32-bit only. The tooling detects and skips
  `amd64` binaries rather than producing unreliable output.

## Architecture

A single-block, single-head causal transformer, then a flatten-and-classify head. The
entire forward pass is `src/lib/attention.py` — about 40 lines of NumPy.

```
tokens[20]
   |
   +-- token embedding  emb[8036, 1643]  +  positional  pe_emb[20, 1643]
   |
   +-- single-head causal self-attention           Wq, Wk, Wv : [1643, 1643]
   |     softmax(Q K^T / sqrt(d_k) + causal_mask) V
   |
   +-- MLP        1643 -> 6572 -> 1643             ReLU
   |
   +-- LayerNorm  [1643]
   |
   +-- flatten    [20 x 1643] -> [32860]
   |
   +-- linear classifier  lm_head[32860, 8036]
   |
logits[8036]  ->  top-5
```

Note the ordering: LayerNorm is applied **after** the MLP (post-norm), there is no
residual connection around either sublayer, and attention has no output projection
(`Wo`) -- its result feeds the MLP directly. This is not a GPT block; it is a purpose-built
minimal architecture, and reimplementations should follow `attention.py` rather than
assume standard transformer conventions.

| Component | Shape | Parameters | Share |
|---|---|---:|---:|
| Token embedding `emb` | `[8036, 1643]` | 13,203,148 | 4.3% |
| Positional embedding `pe_emb` | `[20, 1643]` | 32,860 | 0.0% |
| Attention `Wq`, `Wk`, `Wv` | `3 x [1643, 1643]` | 8,098,347 | 2.6% |
| MLP up `att_seq_ln1` | `[1643, 6572]` + bias | 10,804,368 | 3.5% |
| MLP down `att_seq_ln2` | `[6572, 1643]` + bias | 10,799,439 | 3.5% |
| LayerNorm `att_seq_laynorm` | `2 x [1643]` | 3,286 | 0.0% |
| Classifier `lm_head` | `[32860, 8036]` + bias | 264,070,996 | **86.0%** |
| **Total** | | **307,012,444** | 100% |

The classifier head is 86% of the model: it maps the flattened 20-slot sequence directly
to the vocabulary, without weight tying to the embedding. That single design choice is
why a model with a 1643-dimensional hidden state weighs 1.2 GB, and it is the obvious
first target for anyone wanting a smaller checkpoint.

## Vocabulary

8,036 tokens, shared between the input embedding and the output classifier.

| Group | Count | Examples |
|---|---:|---|
| Win32 API names | 1,445 | `VirtualAlloc`, `RegQueryValueExA`, `WideCharToMultiByte` |
| Integer / flag constants, verbatim | 6,408 | `0x00000040`, `0x00000104`, `0x406d1388` |
| Symbolic argument tokens | 28 | `NULL`, `MEM_BUFF`, `LOCAL_BUFF`, `STR_ANSI_n`, `STR_UNICODE_n`, `DLL_IMG_PTR`, `FUNC_RET`, `RET_OF_FUNC0..14` |
| Other symbols | 155 | kernel-mode routines (`ExAllocatePoolWithTag`, `IoCreateDevice`), C++ and Borland-mangled names |

Two things worth knowing about that table:

- **Constants dominate the vocabulary.** 80% of the tokens are literal integers, kept
  verbatim rather than bucketed. This is what lets the model recognise `0x3000` and
  `0x40` as `VirtualAlloc`'s flags, and it is also why the vocabulary carries a long tail
  of constants seen once during training.
- **The "other symbols" group is a fingerprint of the training corpus** — it includes
  `ntoskrnl` routines and Borland/Delphi mangled names, even though `scan.py` refuses
  Delphi binaries at analysis time. These tokens are reachable in principle but are not
  the model's intended output space.

At inference time any token not in the vocabulary collapses to `MEM_BUFF`
(`attention.py:update_vocab`), so unseen constants degrade to "some pointer" rather than
failing.

## Checkpoint format

The file is a pickled 11-element tuple, in this order:

```python
(stoi, itos, vocab_size, n_embd,
 npwQKV,            # [Wq, Wk, Wv]
 att_seq_ln1,       # [W, b]  MLP up
 att_seq_ln2,       # [W, b]  MLP down
 att_seq_laynorm,   # [gamma, beta]
 emb, pe_emb,
 lm_head)           # [W, b]
```

`stoi` / `itos` are the plain `str <-> int` vocabulary maps; every weight is a
`numpy.float32` array. `BLOCK_SIZE = 20` is a constant in `attention.py`, not stored in
the checkpoint.

Migrating this to `safetensors` plus a JSON vocabulary is on the
[roadmap](README.md#roadmap): it removes the code-execution risk of pickle and makes the
weights loadable from any language.

## Training

The training corpus, the labelling process, and the training code are **not part of this
release**. The methodology is described in the Black Hat USA 2024 talk
([slides](https://i.blackhat.com/BH-US-24/Presentations/REVISED_US24-Ma-Attention-Is-All-You-Need-for-Semantics-Detection-A-Novel-Transformer-on-Neural-Symbolic-Approach-Thursday.pdf)).
This repository ships inference plus the three analysis tools built on it.

What the checkpoint itself tells you about the corpus: it was drawn from real x86 PE
binaries compiled by several toolchains (MSVC, Borland/Delphi) and includes at least
some kernel-mode code, with argument tokenization performed by the same `scan.py`
pipeline used at inference — so training and inference share one tokenizer, and there is
no train/serve skew in the representation.

## Evaluation

Measured results are in the talk slides. For a local sanity check, the two reproducible
runs in the [README](README.md#usage) — a benign 32-bit `winver.exe` and a 22-byte
Cobalt Strike-style shellcode blob — exercise the whole pipeline in under 20 seconds and
require no malware sample.

A public, reproducible benchmark is on the roadmap and is the single most useful thing a
contributor could add.

## Risks and limitations

- **Ranked guesses, not facts.** Anything downstream of this model should treat the
  output as a hypothesis to verify, especially for APIs with fewer than four arguments.
- **Coverage is bounded by emulation.** Call sites vivisect cannot reach are simply
  absent from the output. Silence is not evidence of absence.
- **Argument counts are recovered heuristically** by counting `push` instructions
  (`scan.py:getArgLenList`); when that estimate is wrong the argument-count filter can
  discard the correct answer.
- **32-bit only**, and VB6 / Borland / Delphi binaries are refused outright.
- **Loading the checkpoint executes code**, because it is a pickle. See
  [SECURITY.md](SECURITY.md).
- **Dual-use.** The same capability that names APIs in malware also tells an attacker
  which argument shapes are most identifiable. It is published because defenders,
  triage pipelines, and rule authors need it more than attackers do — an attacker already
  knows what their own loader calls.

## Citation

See [README.md](README.md#research).
