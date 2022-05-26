#!/bin/bash

### Set this to path to mwcc and version on your PC
cd /home/user/tools/mwcc_compiler/1.2.5  

### change any compile flags here, and remove wine if you are using windows ofc.
wine mwcceppc.exe -Cpp_exceptions off -proc gekko -fp hard -fp_contract on -O4,p -enum int -nodefaults -inline auto -c -o $3 $1

### Also ensure that `powerpc-eabi-objdump` is in your environment PATH var
