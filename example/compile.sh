#!/bin/bash

#arm-none-eabi-gcc -mthumb -mthumb-interwork -mcpu=arm7tdmi -O2 -c $* 
cpp $1 | agbcc -mthumb-interwork -O2 -fhex-asm -o ${1%c*}s
arm-none-eabi-as -mthumb -mthumb-interwork -mcpu=arm7tdmi ${1%c*}s -o $3
