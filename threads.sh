#!/bin/bash

for NODES in 8 10 12 14 16 18 20 22 24 26 28 30
do
for THREADS in 1 2 4
do
./run.sh -n $NODES -t $THREADS -T 1 -s 4
done
done