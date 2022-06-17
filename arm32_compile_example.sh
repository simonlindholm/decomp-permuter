#!/bin/bash

### NOTE: Ensure that `arm-none-eabi-objdump` is in your environment PATH var.

### Set this to the root of your decomp project repository.
WORKING_DIR="/home/user/pokeheartgold"

### Set this to the relative path of the C compiler in your repo.
CC="tools/mwccarm/2.0/sp2p2/mwccarm.exe"

C_NAME="$1"
O_NAME="$3"

pushd $WORKING_DIR

### Change any compile flags here, and remove wine if you are using windows ofc.
wine $CC -O4,p -enum int -lang c99 -Cpp_exceptions off -gccext,on -proc arm946e -msgstyle gcc -gccinc -i ./include -ipa file -interworking -inline on,noauto -char signed -gccdep -MD -c -o $O_NAME $C_NAME

popd
