from dataclasses import dataclass, field
import difflib
import hashlib
import re
from typing import Tuple, List, Optional
from collections import Counter
from .objdump import ArchSettings, Line, objdump, get_arch


@dataclass(init=False, unsafe_hash=True)
class DiffAsmLine:
    line: str = field(compare=False)
    mnemonic: str
    has_symbol: bool

    def __init__(self, line: str, has_symbol: bool) -> None:
        self.line = line
        self.mnemonic = line.split(None, 1)[0]
        self.has_symbol = has_symbol


class Scorer:
    PENALTY_INF = 10 ** 9

    PENALTY_STACKDIFF = 1
    PENALTY_REGALLOC = 5
    PENALTY_REORDERING = 60
    PENALTY_INSERTION = 100
    PENALTY_DELETION = 100

    def __init__(self, target_o: str, *, stack_differences: bool):
        self.target_o = target_o
        self.arch = get_arch(target_o)
        self.stack_differences = stack_differences
        _, self.target_seq = self._objdump(target_o)
        self.differ: difflib.SequenceMatcher[DiffAsmLine] = difflib.SequenceMatcher(
            autojunk=False
        )
        self.differ.set_seq2(self.target_seq)

    def _objdump(self, o_file: str) -> Tuple[str, List[DiffAsmLine]]:
        ret = []
        lines = objdump(o_file, self.arch, stack_differences=self.stack_differences)
        for line in lines:
            rows = map(lambda x: x.row, lines)
            ret.append(DiffAsmLine(line.row, line.has_symbol))
        return "\n".join(rows), ret

    def score(self, cand_o: Optional[str]) -> Tuple[int, str]:
        if not cand_o:
            return Scorer.PENALTY_INF, ""

        objdump_output, cand_seq = self._objdump(cand_o)

        score = 0
        deletions = []
        insertions = []

        def field_matches_any_symbol(field: str, arch: ArchSettings) -> bool:
            if arch.name == "ppc":
                if "...data" in field:
                    return True

                parts = field.rsplit("@", 1)
                if len(parts) == 2 and parts[1] in {"l", "h", "ha", "sda21"}:
                    field = parts[0]

                return re.fullmatch((r"^@\d+$"), field) is not None

            if arch.name == "mips":
                return "." in field

            return False

        def diff_sameline(old_line: DiffAsmLine, new_line: DiffAsmLine) -> None:
            nonlocal score
            old = old_line.line
            new = new_line.line

            if old == new:
                return

            ignore_last_field = False
            if self.stack_differences:
                oldsp = re.search(self.arch.re_sprel, old)
                newsp = re.search(self.arch.re_sprel, new)
                if oldsp and newsp:
                    oldrel = int(oldsp.group(1) or "0", 0)
                    newrel = int(newsp.group(1) or "0", 0)
                    score += abs(oldrel - newrel) * self.PENALTY_STACKDIFF
                    ignore_last_field = True

            # Probably regalloc difference, or signed vs unsigned

            # Compare each field in order
            newfields, oldfields = new.split(","), old.split(",")
            if ignore_last_field:
                newfields = newfields[:-1]
                oldfields = oldfields[:-1]
            else:
                # If the last field has a parenthesis suffix, e.g. "0x38(r7)"
                # we split that part out to make it a separate field
                # however, we don't split if it has a proceeding %hi/%lo  e.g."%lo(.data)" or "%hi(.rodata + 0x10)"
                re_paren = re.compile(r"(?<!%hi)(?<!%lo)\(")
                oldfields = oldfields[:-1] + re_paren.split(oldfields[-1])
                newfields = newfields[:-1] + re_paren.split(newfields[-1])

            for nf, of in zip(newfields, oldfields):
                if nf != of:
                    # If the new field is a match to any symbol case
                    # and the old field had a relocation, then ignore this mismatch
                    if field_matches_any_symbol(nf, self.arch) and old_line.has_symbol:
                        continue
                    score += self.PENALTY_REGALLOC

            # Penalize any extra fields
            score += abs(len(newfields) - len(oldfields)) * self.PENALTY_REGALLOC

        def diff_insert(line: str) -> None:
            # Reordering or totally different codegen.
            # Defer this until later when we can tell.
            insertions.append(line)

        def diff_delete(line: str) -> None:
            deletions.append(line)

        self.differ.set_seq1(cand_seq)
        for (tag, i1, i2, j1, j2) in self.differ.get_opcodes():
            if tag == "equal":
                for k in range(i2 - i1):
                    diff_sameline(self.target_seq[j1 + k], cand_seq[i1 + k])
            if tag == "replace" or tag == "delete":
                for k in range(i1, i2):
                    diff_insert(cand_seq[k].line)
            if tag == "replace" or tag == "insert":
                for k in range(j1, j2):
                    diff_delete(self.target_seq[k].line)

        insertions_co = Counter(insertions)
        deletions_co = Counter(deletions)
        for item in insertions_co + deletions_co:
            ins = insertions_co[item]
            dels = deletions_co[item]
            common = min(ins, dels)
            score += (
                (ins - common) * self.PENALTY_INSERTION
                + (dels - common) * self.PENALTY_DELETION
                + self.PENALTY_REORDERING * common
            )

        return (score, hashlib.sha256(objdump_output.encode()).hexdigest())
