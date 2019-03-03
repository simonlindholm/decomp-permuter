import math

class Perm():
    def __init__(self):
        self.perm_count = 1
        self.next_perm = None
        
    def evaluate(self, seed):
        if self.perm_count == 1:
            my_eval = self._evaluate_self(None)
            next_eval = self.next_perm.evaluate(seed) if self.next_perm else ''
        else:
            my_eval = self._evaluate_self(seed[0])
            next_eval = self.next_perm.evaluate(seed[1:]) if self.next_perm else ''

        return my_eval + next_eval

    def _evaluate_self(self, seed):
        return ''

    def get_counts(self):
        self_count = [self.perm_count] if self.perm_count > 1 else []
        next_count = self.next_perm.get_counts() if self.next_perm else []
        return self_count + next_count
       
class TextPerm(Perm):
    def __init__(self, text):
        super().__init__()
        self.text = text

    def _evaluate_self(self, seed):
        return self.text

class RandomizerPerm(Perm):
    def _pragmate_text(self, text):
        return ("\n"
        + "#pragma randomizer_start\n" 
        + text + "\n"
        + "#pragma randomizer_end\n")

    def __init__(self, text):
        super().__init__()
        self.text = self._pragmate_text(text)
        self.perm_count = math.inf

    def _evaluate_self(self, seed):
        return self.text

class GeneralPerm(Perm):
    def __init__(self, candidates):
        super().__init__()
        self.perm_count = len(candidates)
        self.candidates = candidates

    def _evaluate_self(self, seed):
        return self.candidates[seed]
        
