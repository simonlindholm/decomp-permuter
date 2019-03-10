# Decomp permuter

Automatically permutes C files to better match a target binary. The permuter has two modes of operation:
- Random: purely at random, introduce temporary variables for values, change types, put statements on the same line...
- Manual: test all combinations of user-specified variations, using macros like `PERM_TERNARY(a = , b, c, d)` to try both `a = b ? c : d` and `if (b) a = c; else a = d;`.

The modes can also be combined, by using the `PERM_RANDOMIZE` macro.

[<img src="https://asciinema.org/a/232846.svg" height="300" />](https://asciinema.org/a/232846)

## Usage

The permuter expects as input one or more directory containing:
  - a .c file with a single function,
  - a .o file to match,
  - a .sh file that compiles the .c file.

See USAGE.md for more details on how to set these up.

The .c file may be modified with any of the following macros which affect manual permutation:

- `PERM_GENERAL(a, b, ...)` expands to any of `a`, `b`, ...
- `PERM_TYPECAST(a, b, ...)` expands to any of `(a)`, `(b)`, ... (empty argument for no cast at all)
- `PERM_TERNARY(prefix, a, b, c)` expands to either `prefix a ? b : c` or `if (a) prefix b; else prefix c;`.
- `PERM_VAR(a, b)` sets the meta-variable `a` to `b`, `PERM_VAR(a)` expands to the meta-variable `a`.
- `PERM_RANDOMIZE(code)` expands to `code`, but allows randomization within that region. (Right now this region restriction is not
implemented: randomization happens in the entire function.)

Nested macros are allowed, so e.g.
```
PERM_VAR(delayed, )
PERM_GENERAL(stmt;, PERM_VAR(delayed, stmt;))
...
PERM_VAR(delayed)
```
is a valid pattern for emitting a statement either at one point or later.

## FAQ

**What do the scores mean?** The scores are computed by taking diffs of objdump'd .o files, and giving different penalties for lines
that are the same/use the same instruction/are reordered/don't match at all. See scorer.py. It's far from a perfect system, and
should probably be tweaked to look at e.g. the register diff graph.

**What sort of non-matchings are the permuter good at?** It's generally best towards the end, when mostly regalloc changes remain.
If there are reorderings or functional changes, it's often easy to resolve those by hand, and neither the scorer nor the
randomizer tends to play well with them.

**Should I use this instead of trying to match code by hand?** Well, the manual PERM macros might speed you up if you manage
to fit the permuter into your workflow. The random mode is however much more of a last ditch sort of thing.
If often finds nonsensical permutations that happen to match regalloc very well by accident.
Still, it may be useful in pointing out which parts of the code need to be changed to get the code nearer to matching.
