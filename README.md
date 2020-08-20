# An Implementation of the Three Phase Protocol

## usage

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

## Dependencies
* OpenSSL
* Boost.Asio (version 1.72.0)
* CryptoPP (version 8.2)