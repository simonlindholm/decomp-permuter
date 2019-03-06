from typing import Tuple, List, Optional
import os
import re
import subprocess
import hashlib
import difflib

import attr

@attr.s(init=False, hash=True)
class DiffAsmLine:
    line: str = attr.ib(cmp=False)
    mnemonic: str = attr.ib()
    macro_arg: str = attr.ib()

    def __init__(self, line: str) -> None:
        self.line = line
        self.mnemonic = line.split('\t')[0]
        if '%' in line and 'rodata' not in line and 'jtbl' not in line:
            self.macro_arg = '%' + line.split('%')[1].split(')')[0] + ')'
        else:
            self.macro_arg = ''

class Scorer:
    PENALTY_INF = 10**9

    PENALTY_REGALLOC = 10
    PENALTY_SPLIT_DIFF = 20
    PENALTY_REORDERING = 60
    PENALTY_INSERTION = 100
    PENALTY_DELETION = 100

    def __init__(self, target_o: str):
        self.target_o = target_o
        _, self.target_seq = self._objdump(target_o)
        self.differ: difflib.SequenceMatcher[DiffAsmLine] = \
                difflib.SequenceMatcher(autojunk=False)
        self.differ.set_seq2(self.target_seq)

    def _objdump(self, o_file: str) -> Tuple[str, List[DiffAsmLine]]:
        ret = []
        output = subprocess.check_output(['./objdump.sh', o_file]).decode()
        for line in output.split('\n'):
            ret.append(DiffAsmLine(line))
        return (output, ret)

    def score(self, cand_o: str) -> Tuple[int, str]:
        objdump_output, cand_seq = self._objdump(cand_o)
        os.remove(cand_o)

        score = 0
        deletions = []
        insertions = []

        def diff_sameline(old: str, new: str) -> None:
            nonlocal score
            if old == new:
                return
            # Probably regalloc difference, or signed vs unsigned
            score += self.PENALTY_REGALLOC

        def diff_insert(line: str) -> None:
            # Reordering or totally different codegen.
            # Defer this until later when we can tell.
            insertions.append(line)

        def diff_delete(line: str) -> None:
            deletions.append(line)

        first_ins = None
        self.differ.set_seq1(cand_seq)
        for (tag, i1, i2, j1, j2) in self.differ.get_opcodes():
            if tag == 'equal':
                for k in range(i2 - i1):
                    old = self.target_seq[j1 + k].line
                    new = cand_seq[i1 + k].line
                    diff_sameline(old, new)
            if tag == 'replace' or tag == 'delete':
                for k in range(i1, i2):
                    diff_insert(cand_seq[k].line)
            if tag == 'replace' or tag == 'insert':
                for k in range(j1, j2):
                    diff_delete(self.target_seq[k].line)

        common = set(deletions) & set(insertions)
        score += len(common) * self.PENALTY_REORDERING
        for change in deletions:
            if change not in common:
                score += self.PENALTY_DELETION
        for change in insertions:
            if change not in common:
                score += self.PENALTY_INSERTION
        return (score, hashlib.sha256(objdump_output.encode()).hexdigest())
