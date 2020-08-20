#!/bin/bash

usage()
{
    echo "usage: run.sh [OPTIONS]"
	echo "	-h --help				This help message"
	echo "	-n --nodes		NUM		number of nodes (default: 8)"
	echo "	-T --type		0|1		security mode 0 is unsecure, 1 is secured (default: 0)"
	echo "	-t --threads		NUM		number of threads (default: 1)"
	echo "	-s --senders		NUM		number of senders (default: 1)"
	echo "	-m --msgsize		NUM		size of message in byte (default: 512)"
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
								echo "using nodes as $1"
                                export nodes=$1
                                ;;
        -T | --type )           shift
								echo "using type as $1"
                                export type=$1
                                ;;
        -t | --threads )        shift
								echo "using threads as $1"
                                export threads=$1
                                ;;
        -s | --senders )        shift
								echo "using senders as $1"
                                export senders=$1
                                ;;
        -m | --msgsize )        shift
								echo "using mesagesize as $1"
                                export msgsize=$1
                                ;;
        -d | --delay )          shift
								echo "using delay as $1"
                                export delay=$1
                                ;;
        -h | --help) usage
								exit
                                ;;
    esac
    shift
done

docker-compose up --build --scale three-pp-container=${nodes}