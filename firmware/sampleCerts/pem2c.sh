#!/bin/sh

if [ $# -lt 1 ]; then
 echo "ERROR: input filename must be provided as an argument"
 exit
fi

if [ ! -f "$1" ]; then
 echo "ERROR: $1 not found"
 exit
fi

sed -n '/-----BEGIN/,/-----END/{/-----/d;p}' "$1" | base64 -di | xxd -c16 -i | sed -e 's/0x/\\x/g ; s/, //g ; s/^  /\t"/g ; s/,*$/"/g ; $ s/$/;/ ; 1 i\static const unsigned char c[] =' 

#tr -cd x | wc -c

