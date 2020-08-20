#!/bin/bash

export nodes=8
export type=0
export threads=1
export senders=1
export msgsize=512
export delay=100

while [ "$1" != "" ]; do
    case $1 in
        -n | --nodes )          shift
								echo "rewrite nodes to $1"
                                export nodes=$1
                                ;;
        -T | --type )           shift
								echo "rewrite type to $1"
                                export type=$1
                                ;;
        -t | --threads )        shift
								echo "rewrite threads to $1"
                                export threads=$1
                                ;;
        -s | --senders )        shift
								echo "rewrite senders to $1"
                                export senders=$1
                                ;;
        -m | --msgsize )        shift
								echo "rewrite mesagesize to $1"
                                export msgsize=$1
                                ;;
        -d | --delay )          shift
								echo "rewrite delay to $1"
                                export delay=$1
                                ;;
    esac
    shift
done

#docker-compose up --build --scale three-pp-container=${nodes}