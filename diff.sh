#!/bin/bash

if [ $# < 2 ]; then
	echo "Usage: $0 orig.o new.o [flags]"
	exit 1
fi

if [ ! -f $1 -o ! -f $2 ]; then
	echo Source files not readable
	exit 1
fi

INPUT1="$1"
INPUT2="$2"
shift
shift
wdiff -n <(./objdump.sh "$INPUT1" "$@") <(./objdump.sh "$INPUT2" "$@") | colordiff | less
