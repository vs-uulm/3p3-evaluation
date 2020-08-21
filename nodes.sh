#!/bin/bash

for NODES in 8 10 12 14 16 18 20 22 24
do
for TYPE in 0 1
do
./run.sh -n $NODES -t 4 -T $TYPE -s 4
done
done