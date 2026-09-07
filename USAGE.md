This file describes how to manually set up a directory for use with the permuter.
**You probably don't need to do this!** In normal circumstances, `./import.py`
does all this for you. See README.md for more details.

* create a directory that will contain all of the input files for the invokation
* put a compile command into `<dir>/compile.sh` (see e.g. `compile_example.sh`; it will be invoked as `./compile.sh input.c -o output.o`)
* optionally create a toml file at `<dir>/settings.toml` (see `example_settings.toml` for reference)
* `gcc -E -P -I header_dir -D'__attribute__(x)=' orig_c_file.c > <dir>/base.c`
* `python3 strip_other_fns.py <dir>/base.c func_name`
* put asm for `func_name` into `<dir>/target.s`, together with the header from `prelude.inc`
* `mips-linux-gnu-as -march=vr4300 -mabi=32 <dir>/target.s -o <dir>/target.o`
* optional sanity check:
  - `<dir>/compile.sh <dir>/base.c -o <dir>/base.o`
  - `./permuter.py <dir> --debug`
* `./permuter.py <dir>`

## Scoring modes

`--score-mode reloc-masked` (or `score_mode = "reloc-masked"` in settings.toml) switches
MIPS targets from the default mnemonic diff to a comparison of raw instruction words,
with the fields the linker fills in masked based on the target's relocation records
(see `src/reloc_scorer.py`). The score is the number of instructions that differ plus the
length difference, so it is 0 exactly when the candidate links to the same bytes. This
helps in projects whose symbols don't contain a "." (e.g. `func_80012345`), where the
default scorer can't tell a relocation slot from a register difference and gets stuck
above 0. `--debug` prints the differing instructions. Not available together with `-J`.
