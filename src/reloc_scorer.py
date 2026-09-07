"""Relocation-masked scorer for MIPS (--score-mode reloc-masked).

Compares the raw instruction words of the candidate and target objects. Fields
that the linker fills in are masked based on the target's relocation records:

* R_MIPS_26 (j/jal): keep the opcode, mask the 26-bit target.
* 16-bit relocations (HI16/LO16/PC16/LITERAL/GPREL16/GOT16/CALL16): keep
  opcode + rs + rt, mask the immediate.

At a masked position the relocation symbol (plus addend) still has to match.
A `j` relocated against .text (a jump to a label in the same function) is
compared by its target relative to the start of the function. Everything else
is compared as a full word, registers included.

The score is the number of positions that differ plus the difference in
instruction count, so it is 0 exactly when the candidate would link to the
same bytes. This gives the permuter a gradient down to 0 in projects whose
symbols never contain a "." (e.g. splat's func_80012345), where the default
scorer treats every relocation slot with a different symbol name as a
register difference and never reaches 0.
"""

import hashlib
import re
import shlex
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from .objdump import find_executable, get_arch
from .scorer import Scorer

_HDR_RE = re.compile(r"^[0-9a-f]+ <([^>]+)>:")
_INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)")
_RELOC_RE = re.compile(r"R_MIPS_(\w+)\s+(\S+)")
_IMM16_RELOCS = {"HI16", "LO16", "PC16", "LITERAL", "GPREL16", "GOT16", "CALL16"}

MASK_FULL = 0xFFFFFFFF
MASK_OPCODE = 0xFC000000
MASK_NO_IMM16 = 0xFFFF0000


@dataclass
class Insn:
    offset: int
    word: int
    text: str
    reloc_kind: Optional[str] = None
    reloc_op: Optional[str] = None
    jrel: Optional[int] = None  # target of an in-function j, relative to fn start


def mask_for(reloc_kind: Optional[str]) -> int:
    if reloc_kind == "26":
        return MASK_OPCODE
    if reloc_kind in _IMM16_RELOCS:
        return MASK_NO_IMM16
    return MASK_FULL


def parse_listing(lines: Sequence[str], fn_name: Optional[str] = None) -> List[Insn]:
    """Parse `objdump -dr` output. With fn_name, restrict to that function if the
    listing has it; otherwise use all of .text (same scope as the default scorer)."""
    insns: List[Insn] = []
    fn_start: Optional[int] = None
    in_fn = fn_name is None
    for line in lines:
        header = _HDR_RE.match(line)
        if header:
            in_fn = fn_name is None or header.group(1) == fn_name
            continue
        if not in_fn:
            continue
        m = _INSN_RE.match(line)
        if m:
            offset = int(m.group(1), 16)
            if fn_start is None:
                fn_start = offset
            insns.append(Insn(offset, int(m.group(2), 16), m.group(3).strip()))
            continue
        reloc = _RELOC_RE.search(line)
        if reloc and insns:
            insns[-1].reloc_kind = reloc.group(1)
            insns[-1].reloc_op = reloc.group(2)
    if fn_name is not None and not insns:
        return parse_listing(lines, None)
    start = fn_start or 0
    for insn in insns:
        if (
            (insn.word >> 26) == 2
            and insn.reloc_kind == "26"
            and insn.reloc_op == ".text"
        ):
            insn.jrel = ((insn.word & 0x3FFFFFF) << 2) - start
    return insns


def classify(cand: Insn, target: Insn) -> Optional[str]:
    """Return None if the two instructions match up to relocation, else a reason."""
    mask = mask_for(target.reloc_kind)
    if (cand.word & mask) != (target.word & mask):
        if (cand.word >> 26) != (target.word >> 26):
            return "opcode"
        return "operand"
    if cand.jrel is not None and target.jrel is not None and cand.jrel != target.jrel:
        return "jump target"
    if mask != MASK_FULL and (cand.reloc_op or "") != (target.reloc_op or ""):
        return "relocation symbol"
    return None


def masked_diff(
    cand: Sequence[Insn], target: Sequence[Insn]
) -> Tuple[int, List[Tuple[int, Optional[Insn], Optional[Insn], str]]]:
    """Return (score, diffs) where diffs lists (index, cand, target, reason)."""
    diffs: List[Tuple[int, Optional[Insn], Optional[Insn], str]] = []
    for i in range(max(len(cand), len(target))):
        if i >= len(cand) or i >= len(target):
            diffs.append(
                (
                    i,
                    cand[i] if i < len(cand) else None,
                    target[i] if i < len(target) else None,
                    "length",
                )
            )
            continue
        reason = classify(cand[i], target[i])
        if reason is not None:
            diffs.append((i, cand[i], target[i], reason))
    return len(diffs), diffs


class RelocMaskedScorer(Scorer):
    """Scorer that compares relocation-masked instruction words. Doesn't call
    Scorer.__init__ since none of the mnemonic-diff state is used; the public
    interface (score(), PENALTY_INF, target_o, arch, debug_mode,
    objdump_command) is the same."""

    def __init__(
        self,
        target_o: str,
        *,
        fn_name: Optional[str] = None,
        debug_mode: bool = False,
        objdump_command: Optional[str] = None,
    ):
        self.target_o = target_o
        self.arch = get_arch(target_o)
        if self.arch.name != "mips":
            raise ValueError(
                f"reloc-masked scoring supports MIPS objects only, not {self.arch.name}"
            )
        self.fn_name = fn_name
        self.debug_mode = debug_mode
        self.objdump_command = objdump_command or ""
        self.stack_differences = False  # read by net/client.py
        self.algorithm = "reloc-masked"
        self.target_insns = self._insns(target_o)

    def _insns(self, o_file: str) -> List[Insn]:
        if self.objdump_command:
            command = shlex.split(self.objdump_command)
        else:
            command = [find_executable(tuple(self.arch.executable), self.arch.name)]
            command += ["-drz", "-j", ".text"]
        output = subprocess.check_output(command + [o_file]).decode("utf-8", "replace")
        return parse_listing(output.splitlines(), self.fn_name)

    def score(self, cand_o: Optional[str]) -> Tuple[int, str]:
        if not cand_o:
            return Scorer.PENALTY_INF, ""
        cand = self._insns(cand_o)
        if not cand:
            return Scorer.PENALTY_INF, ""
        value, diffs = masked_diff(cand, self.target_insns)
        if self.debug_mode:
            for index, c, t, reason in diffs:
                left = f"{c.word:08x} {c.text}" if c else "--"
                right = f"{t.word:08x} {t.text}" if t else "--"
                print(f"#{index:<4} {left:40.40s} | {right:40.40s} {reason}")
            print(
                f"reloc-masked score: {value} ({len(cand)} vs {len(self.target_insns)} insns)"
            )
        digest = hashlib.sha256(
            "".join(
                f"{i.word:08x}:{i.reloc_kind or ''}:{i.reloc_op or ''};" for i in cand
            ).encode()
        ).hexdigest()
        return value, digest
