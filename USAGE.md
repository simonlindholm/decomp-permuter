This file describes how to manually set up a directory for use with the permuter.
**You probably don't need to do this!** In normal circumstances, `./import.py`
does all this for you. See README.md for more details.

* create a directory that will contain all of the input files for the invokation
* put a compile command into `<dir>/compile.sh` (see e.g. `compile_example.sh`; it will be invoked as `./compile.sh input.c -o output.o`)
* `gcc -E -P -I header_dir -D'__attribute__(x)=' orig_c_file.c > <dir>/base.c`
* `python3 strip_other_fns.py <dir>/base.c func_name`
* put asm for `func_name` into `<dir>/target.s`, with the following header:

```asm
.set noat
.set noreorder
.set gp=64
.macro glabel label
    .global \label
	.type \label, @function
    \label:
.endm
```
* `mips-linux-gnu-as -march=vr4300 -mabi=32 <dir>/target.s -o <dir>/target.o`
* optional sanity checks:
  - `<dir>/compile.sh <dir>/base.c -o <dir>/base.o`
  - `./diff.sh <dir>/target.o <dir>/base.o`
* `./permuter.py <dir>`


## Using import.py with decomp.me
import.py has an additional feature where it can prepare a directory for the permuter by downloading what it needs from a decomp.me scratch. 
To use this feature all you need to do is put a script called "compile.sh" in the current working directory (root of this repository) that compiles a .c file.  (See mips_compile_example.sh or mwcc_compile_example.sh)
Then run: `python3 import.py https://decomp.me/scratch/AbC12`