# Instructions for Permuting with MWCC

## General Description

Note: this permuter is WIP, has many limitations, may not be very optimized, and may not fully cleanup after itself.

 This fork is setup to compile the C code with mwcc (using wine) to an object file then dump with objdump to a text file, then the scoring is done by post processing the text files as a string and using a diff check. It is possible (likely) that this process could be done better by just compiling to binary object file and doing the scoring by comparing the object files with a different method. 

 - The C code permutation is unchanged from the original repository. 
 - The compile script uses mwcc1.2.5 (no e) (and no frank) (using wine) (but this could
   be modded if you choose) then does powerpc-eabi-objdump then post
   processes the dump text with nodejs.
- The scoring works by performing a diff on post-processed dump files and counting the different lines.
   
### Additional Prerequisite
Some basic text processing is done with nodejs, so that will need to be installed.  If people oppose this, it could be easily redone in python.

## File Setup
Similar to the original permuter this was forked from, `./permuter.py directory/` runs the permuter; see below for the meaning of the directory. Pass `-h` to see possible flags. `-j` is suggested (enables multi-threaded mode).

  You'll first need to install a couple of prerequisites: `python3 -m pip install pycparser pynacl toml` (also `dataclasses` if on Python 3.6 or below)

However the directory requirements are different. This directory can be located anywhere and named anything but must contain 5 items:

 - mwcceppc.exe,  must be 1.2.5 (not 1.2.5e)
 - lmgr326b.dll,  from the mwcc compiler folder
 - base.c,  A source file containing a single function to permute
	 - Note, you can use all PERM() macros from the original repo for manually specifying permutation rules
	 - Note, if you have any inlines that your function needs, you must wrap those in `PERM_IGNORE()`
 - ctx.h,  the context to compile that source file (make sure base.c includes ctx.h at the top)
 - target obj dump file (presumably one that is matching, because that's the goal) 
	 - Here is an example command to create the target dump file
	 - `$DEVKITPPC/bin/powerpc-eabi-objdump -D -bbinary -EB -mpowerpc -M gekko --start-address=0x6A69C --stop-address=0x6A7D4 --no-addresses ~/Personal/melee/baserom.dol > matching_target.dump`

## Code Setup

Set the function name of the function you want to permute in the code in main.py here:
https://github.com/snuffysasa/decomp-permuter/blob/dcdb9d7d80d92bf4feaf2c1d5c4f48c15251c591/src/main.py#L292
*TODO*:  Make this automatically detect the correct (only) function in base.c

You can verify the permutations and generated C code is working correctly by uncommenting this print line:
https://github.com/snuffysasa/decomp-permuter/blob/dcdb9d7d80d92bf4feaf2c1d5c4f48c15251c591/src/compiler.py#L22

Note: As mentioned before, this does include any of the epilogue fixes which will show up as differences from the matching target.  You can simply tell the scorer to ignore a certain amount of lines (1 instruction per line / bytes) at the bottom of the function.   You can specify that here: https://github.com/snuffysasa/decomp-permuter/blob/dcdb9d7d80d92bf4feaf2c1d5c4f48c15251c591/src/scorer.py#L35
*TODO*:  Make this automatically detect the amount epilogue lines to ignore

The code will by default print any score/result that is less/better than the base score, but you can modify that behavior to be more or less strict here: https://github.com/snuffysasa/decomp-permuter/blob/dcdb9d7d80d92bf4feaf2c1d5c4f48c15251c591/src/permuter.py#L205

You can also optionally set a threshold for printing the source code for good scores/results or quitting stopping the process here: https://github.com/snuffysasa/decomp-permuter/blob/dcdb9d7d80d92bf4feaf2c1d5c4f48c15251c591/src/permuter.py#L209


If you want to view a specific permutation from a specific seed, you can force set a seed here:
https://github.com/snuffysasa/decomp-permuter/blob/dcdb9d7d80d92bf4feaf2c1d5c4f48c15251c591/src/permuter.py#L179


## Running the code

The code must be ran from the root of the repository. And you should specify the amount of threads to use. It's best to start with 1 to verify permuting, compiling and scoring is working correctly first, then increase from there.

```bash
cd decomp-permuter
python3 permuter.py /path/to/directory  -j32
```

