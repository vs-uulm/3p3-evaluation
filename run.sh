#!/bin/bash

usage()
{
    echo "usage: run.sh [OPTIONS]"
	echo "	-h --help				This help message"
	echo "	-n --nodes		NUM		number of nodes (default: 8)"
	echo "	-r --round		0|1		which round to call (default: 0)"
	echo "	-t --threads	NUM		number of threads (default: 1)"
	echo "	-s --senders	NUM		number of senders (default: 1)"
	echo "	-m --msgsize	NUM		size of message in byte (default: 512)"
	echo "	-d --delay		NUM		delay in ms (default: 100)"
}

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
        -r | --round )           shift
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
        -h | --help) usage
								exit
                                ;;
    esac
    shift
done

docker-compose up --build --scale three-pp-container=${nodes}