import difflib
import hashlib
import re
import shlex
from typing import Dict, List, Optional, Sequence, Tuple, Set
from collections import Counter

from .objdump import ArchSettings, Line, objdump, get_arch


class Scorer:
    PENALTY_INF = 10**9

    PENALTY_STACKDIFF = 1
    PENALTY_BRANCHDIFF = 1
    PENALTY_REGALLOC = 5
    PENALTY_REORDERING = 60
    PENALTY_INSERTION = 100
    PENALTY_DELETION = 100

    def __init__(
        self,
        target_o: str,
        *,
        stack_differences: bool,
        algorithm: str,
        debug_mode: bool,
        ign_branch_targets: bool,
        objdump_path: Optional[str],
        objdump_args: Optional[str],
    ):
        self.target_o = target_o
        self.arch = get_arch(target_o)
        self.stack_differences = stack_differences
        self.algorithm = algorithm
        self.debug_mode = debug_mode
        self.objdump_path = objdump_path
        self.objdump_args = objdump_args
        self.ign_branch_targets = ign_branch_targets
        _, self.target_seq = self._objdump(target_o)
        self.difflib_differ: difflib.SequenceMatcher[str] = difflib.SequenceMatcher(
            autojunk=False
        )
        self.difflib_differ.set_seq2([line.mnemonic for line in self.target_seq])

    def _objdump(self, o_file: str) -> Tuple[str, List[Line]]:
        objdump_args = shlex.split(self.objdump_args) if self.objdump_args else None
        lines = objdump(
            o_file,
            self.arch,
            objdump_path=self.objdump_path,
            objdump_args=objdump_args,
            stack_differences=self.stack_differences,
            ign_branch_targets=self.ign_branch_targets,
        )
        return "\n".join([line.row for line in lines]), lines

    def score(self, cand_o: Optional[str]) -> Tuple[int, str]:
        if not cand_o:
            return Scorer.PENALTY_INF, ""

        objdump_output, cand_seq = self._objdump(cand_o)

        num_stack_penalties: int = 0
        num_branch_penalties: int = 0
        num_regalloc_penalties: int = 0
        num_reordering_penalties: int = 0
        num_insertion_penalties: int = 0
        num_deletion_penalties: int = 0
        deletions: List[str] = []
        insertions: List[str] = []

        def field_matches_any_symbol(field: str, arch: ArchSettings) -> bool:
            if arch.name == "ppc":
                if "..." in field:
                    return True

                parts = field.rsplit("@", 1)
                if len(parts) == 2 and parts[1] in {"l", "h", "ha", "sda21"}:
                    field = parts[0]

                return re.fullmatch(r"^@\d+$", field) is not None

            if arch.name == "mips":
                return "." in field

            # Example: ".text+0x34"
            if arch.name == "arm32":
                return "." in field

            return False

        def diff_sameline(old_line: Line, new_line: Line) -> bool:
            nonlocal num_stack_penalties
            nonlocal num_branch_penalties
            nonlocal num_regalloc_penalties

            old_num_stack_penalties = num_stack_penalties
            old_num_branch_penalties = num_branch_penalties
            old_num_regalloc_penalties = num_regalloc_penalties

            old = old_line.row
            new = new_line.row

            if old == new:
                return False

            ignore_last_field = False
            if self.stack_differences:
                oldsp = re.search(self.arch.re_sprel, old)
                newsp = re.search(self.arch.re_sprel, new)
                if oldsp and newsp:
                    oldrel = int(oldsp.group(1) or "0", 0)
                    newrel = int(newsp.group(1) or "0", 0)
                    num_stack_penalties += abs(oldrel - newrel)
                    ignore_last_field = True

            if not self.ign_branch_targets:
                b_instr = self.arch.branch_instructions
                bl_instr = self.arch.branch_likely_instructions

                if (
                    old_line.mnemonic == new_line.mnemonic
                    and (old_line.mnemonic in b_instr or old_line.mnemonic in bl_instr)
                    and old_line.row != new_line.row
                    and not old_line.has_symbol
                    and not new_line.has_symbol
                ):
                    old_target = old_line.row.split(",")[-1]
                    new_target = new_line.row.split(",")[-1]
                    if old_target != new_target:
                        num_branch_penalties += 1
                        ignore_last_field = True

            # Probably regalloc difference, or signed vs unsigned

            # Compare each field in order
            new_parts, old_parts = new.split(None, 1), old.split(None, 1)
            newfields = new_parts[1].split(",") if len(new_parts) > 1 else []
            oldfields = old_parts[1].split(",") if len(old_parts) > 1 else []
            if ignore_last_field:
                newfields = newfields[:-1]
                oldfields = oldfields[:-1]
            else:
                # If the last field has a parenthesis suffix, e.g. "0x38(r7)"
                # we split that part out to make it a separate field
                # however, we don't split if it has a proceeding %hi/%lo
                # e.g."%lo(.data)" or "%hi(.rodata + 0x10)"
                re_paren = re.compile(r"(?<!%hi)(?<!%lo)\(")
                oldfields = oldfields[:-1] + (
                    re_paren.split(oldfields[-1]) if len(oldfields) > 0 else []
                )
                newfields = newfields[:-1] + (
                    re_paren.split(newfields[-1]) if len(newfields) > 0 else []
                )

            for nf, of in zip(newfields, oldfields):
                if nf != of:
                    # If the new field is a match to any symbol case
                    # and the old field had a relocation, then ignore this mismatch
                    if field_matches_any_symbol(nf, self.arch) and old_line.has_symbol:
                        continue
                    num_regalloc_penalties += 1

            # Penalize any extra fields
            num_regalloc_penalties += abs(len(newfields) - len(oldfields))

            return (
                old_num_regalloc_penalties != num_regalloc_penalties
                or old_num_stack_penalties != num_stack_penalties
                or old_num_branch_penalties != num_branch_penalties
            )

        def diff_insert(line: str) -> None:
            # Reordering or totally different codegen.
            # Defer this until later when we can tell.
            insertions.append(line)

        def diff_delete(line: str) -> None:
            deletions.append(line)

        result_diff: Sequence[Tuple[str, int, int, int, int]]
        if self.algorithm == "levenshtein":
            import Levenshtein

            remapping: Dict[str, str] = {}

            def remap(seq: List[str]) -> str:
                seq = seq[:]
                for i in range(len(seq)):
                    val = remapping.get(seq[i])
                    if val is None:
                        val = chr(len(remapping))
                        remapping[seq[i]] = val
                    seq[i] = val
                return "".join(seq)

            result_diff = Levenshtein.opcodes(
                remap([line.mnemonic for line in cand_seq]),
                remap([line.mnemonic for line in self.target_seq]),
            )
        else:
            self.difflib_differ.set_seq1([line.mnemonic for line in cand_seq])
            result_diff = self.difflib_differ.get_opcodes()

        equal_no_diff: Set[int] = set()
        for tag, i1, i2, j1, j2 in result_diff:
            if tag == "equal":
                for k in range(i2 - i1):
                    old_line = self.target_seq[j1 + k]
                    new_line = cand_seq[i1 + k]
                    if not diff_sameline(old_line, new_line):
                        equal_no_diff.add(i1 + k)
            if tag == "replace" or tag == "delete":
                for k in range(i1, i2):
                    diff_insert(cand_seq[k].row)
            if tag == "replace" or tag == "insert":
                for k in range(j1, j2):
                    diff_delete(self.target_seq[k].row)

        if self.debug_mode:
            # find the max mnemonic length for consistent padding
            mnem_max_len = max(
                *(len(line.mnemonic) for line in self.target_seq),
                *(len(line.mnemonic) for line in cand_seq),
                0,
            )

            def format_line(line: str, mnem_len: int, max_len: Optional[int] = None):
                """
                Split line on first tab to separate the mnemonic from the rest
                of the line. Print the mnemonic as a left-justified string of
                length `mnem_len`, then add the rest of the line. If `max_len`
                is specified, cut the resulting string to `max_len`.
                """
                split = line.split("\t", maxsplit=1)
                if len(split) != 2:
                    return line
                mnem, rest = split
                line_str = f"{mnem:{mnem_len}s}  {rest}"
                if max_len:
                    line_str = line_str[:max_len]
                return line_str

            # Print simple asm diff
            for tag, i1, i2, j1, j2 in result_diff:
                if tag == "equal":
                    for k in range(i2 - i1):
                        old_line = self.target_seq[j1 + k]
                        new_line = cand_seq[i1 + k]
                        same = i1 + k in equal_no_diff
                        color = "\u001b[0m" if same else "\u001b[94m"
                        old_str = format_line(old_line.row, mnem_max_len, 40).ljust(40)
                        new_str = format_line(new_line.row, mnem_max_len)
                        print(f"{color}{old_str}\t{new_str}")
                if tag == "replace" or tag == "delete":
                    for k in range(i1, i2):
                        color = "\u001b[32;1m"
                        old_str = "".ljust(40)
                        new_str = format_line(cand_seq[k].row, mnem_max_len)
                        print(f"{color}{old_str}\t{new_str}")
                if tag == "replace" or tag == "insert":
                    for k in range(j1, j2):
                        color = "\u001b[91;1m"
                        old_str = format_line(self.target_seq[k].row, mnem_max_len)
                        new_str = ""
                        print(f"{color}{old_str}\t{new_str}")

            print("\u001b[0m")

        insertions_co = Counter(insertions)
        deletions_co = Counter(deletions)
        for item in insertions_co + deletions_co:
            ins = insertions_co[item]
            dels = deletions_co[item]
            common = min(ins, dels)
            num_insertion_penalties += ins - common
            num_deletion_penalties += dels - common
            num_reordering_penalties += common

        if self.debug_mode:
            print()
            print("--------------- Penalty List ---------------")
            print(
                "Stack Differences: ".ljust(30),
                num_stack_penalties,
                f" ({self.PENALTY_STACKDIFF})",
            )
            print(
                "Branch Differences: ".ljust(30),
                num_branch_penalties,
                f" ({self.PENALTY_BRANCHDIFF})",
            )
            print(
                "Register Differences: ".ljust(30),
                num_regalloc_penalties,
                f" ({self.PENALTY_REGALLOC})",
            )
            print(
                "Reorderings: ".ljust(30),
                num_reordering_penalties,
                f" ({self.PENALTY_REORDERING})",
            )
            print(
                "Insertions: ".ljust(30),
                num_insertion_penalties,
                f" ({self.PENALTY_INSERTION})",
            )
            print(
                "Deletions: ".ljust(30),
                num_deletion_penalties,
                f" ({self.PENALTY_DELETION})",
            )

        final_score = (
            num_stack_penalties * self.PENALTY_STACKDIFF
            + num_branch_penalties * self.PENALTY_BRANCHDIFF
            + num_regalloc_penalties * self.PENALTY_REGALLOC
            + num_reordering_penalties * self.PENALTY_REORDERING
            + num_insertion_penalties * self.PENALTY_INSERTION
            + num_deletion_penalties * self.PENALTY_DELETION
        )

        return (final_score, hashlib.sha256(objdump_output.encode()).hexdigest())
