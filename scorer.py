import os
import subprocess
import hashlib

class Scorer():
    PENALTY_INF = 10**9

    PENALTY_REGALLOC = 10
    PENALTY_SPLIT_DIFF = 20
    PENALTY_REORDERING = 60
    PENALTY_INSERTION = 100
    PENALTY_DELETION = 100

    def __init__(self, target_o):
        self.target_o = target_o

    def score(self, cand_o):
        if cand_o is None:
            return self.PENALTY_INF, None
        try:
            diff = subprocess.check_output(['./diff.sh', self.target_o, cand_o]).decode()
        finally:
            os.remove(cand_o)
        diffs = 0
        deletions = []
        insertions = []
        for line in diff.split('\n'):
            deletion = '[-' in line
            insertion = '{+' in line
            if not deletion and not insertion:
                continue
            # print(line)
            if deletion and insertion:
                # probably regalloc difference, or signed vs unsigned
                diffs += self.PENALTY_REGALLOC
            elif (line.startswith('[-') and line.endswith('-]')) or (line.startswith('{+') and line.endswith('+}')):
                # reordering or totally different codegen
                # defer this until later when we can tell
                line = line[2:-2]
                if deletion:
                    deletions.append(line)
                else:
                    insertions.append(line)
            else:
                # insertion/deletion split across lines, ugh
                diffs += self.PENALTY_SPLIT_DIFF
        common = set(deletions) & set(insertions)
        diffs += len(common) * self.PENALTY_REORDERING
        for change in deletions:
            if change not in common:
                diffs += self.PENALTY_DELETION
        for change in insertions:
            if change not in common:
                diffs += self.PENALTY_INSERTION
        return (diffs, hashlib.sha256(diff.encode()).hexdigest())