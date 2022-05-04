#!/bin/bash
pwd=`pwd`
cd /home/vsi/Desktop/permute_test
wine mwcceppc125.exe -Cpp_exceptions off -proc gekko -fp hard -fp_contract on -O4,p -enum int -nodefaults -inline auto -c -o $1".tmp" $1  
cd $pwd

OBJDUMP="$DEVKITPPC/bin/powerpc-eabi-objdump -D -bbinary -EB -mpowerpc -M gekko"
$DEVKITPPC/bin/powerpc-eabi-objdump -D -bbinary -EB -mpowerpc -M gekko  --start-address=0x34 --no-addresses $1".tmp" > $2".tmp"
rm $1".tmp"

node new_tools/post_process_dump.js $2".tmp" $2

rm $2".tmp"

