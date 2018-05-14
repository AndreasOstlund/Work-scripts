#!/bin/sh

echo "converting $1"

piconv -f UTF-16 -t UTF-8 $1 > ${1}.utf8

