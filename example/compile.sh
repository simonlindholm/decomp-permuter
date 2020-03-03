#!/bin/bash

#agbcc -mthumb-interwork -O2 $* 
arm-none-eabi-gcc -mthumb -mthumb-interwork -mcpu=arm7tdmi -O2 -c $* 
