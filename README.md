# An Implementation of the Three Phase Protocol

Ths repository contains the evaluation implementation of the three phase privacy preserving broadcast protocol 3P3.

## Repository Structure

The repository is structured in the following way:

### src

src contains the code of the 3P3 implementation in C++.

### docker

The docker folder contains the dockerfiles for the various orchestrated containers.

 * The build container to compile the system.
 * The central container is used to orchestrate the experiment and collect the results.
 * The threePP container runs the actual protocol  implementation.

These are used in the docker-compose.yml file to orchestrate the behaviour.
All files make use of environment variables set through experiment scripts.

### cert 
 
The certificates are use for securing the network communication of the system.
Obviously, these are for experimental use and not production use.
 
### Sample Topologies

Contains network topologies of certain sizes.

## usage

The experiments can be run in two different ways.
All experiments are configured to use 50Mbit/s maximum for their virual interfaces through traffic control.
The generic way uses `run.sh` to run an experiment with a given set of parameters.

```
usage: run.sh [OPTIONS]
        -h --help                               This help message
        -n --nodes              NUM             number of nodes (default: 8)
        -T --type               0|1             security mode 0 is unsecure, 1 is secured (default: 0)
        -t --threads            NUM             number of threads (default: 1)
        -s --senders            NUM             number of senders (default: 1)
        -m --msgsize            NUM             size of message in byte (default: 512)
        -d --delay              NUM             delay in ms (default: 100)
```

The alternative is to run preprepared experiments using one of the experiment files.
These files use a message size of 512 bytes and a delay of 100ms.

 * `threads.sh`: Runs the secure protocol with a number of nodes of 8, 10, 12, ..., 24 with either 1, 2 or 4 threads. (Uses 4 senders.)
 * `nodes.sh`: Runs the protocol with a number of nodes of 8, 10, 12, ...., 24 in either secured or unsecured mode. (Uses 4 threads for the secured mode and 4 senders.)
 * `messages.sh`: Runs the protocol with 1 to 20 senders in either secured or unsecured mode. (It uses 20 nodes, 4 senders and 4 threas for the secured mode.)

## Dependencies
* OpenSSL
* Boost.Asio (version 1.72.0)
* CryptoPP (version 8.2)