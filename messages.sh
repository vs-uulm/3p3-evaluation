#!/bin/bash

for TYPE in 0 1
do
for SENDERS in {1..20}
do
./run.sh -n 20 -t 4 -T $TYPE -s $SENDERS
done
done