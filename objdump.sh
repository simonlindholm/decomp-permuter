#!/bin/bash

if [ $# = 0 ]; then
	echo "Usage: $0 file.o [flags]" >&2
	exit 1
fi

if [ ! -f $1 ]; then
	echo "Source file $1 is not readable." >&2
	exit 1
fi

INPUT="$1"
shift

mips-linux-gnu-objdump -drz $INPUT | python3 simplify_objdump.py "$@"
