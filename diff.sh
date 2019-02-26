#!/bin/bash

if [ $# != 2 ]; then
	echo "Usage: $0 orig.o new.o"
	exit 1
fi

if [ ! -f $1 -o ! -f $2 ]; then
	echo Source files not readable
	exit 1
fi

TRANSFORM="python3 simplify_objdump.py"
OBJDUMP="mips-linux-gnu-objdump -drz"
wdiff -n <($OBJDUMP $1 | $TRANSFORM) <($OBJDUMP $2 | $TRANSFORM) || true
