FROM ubuntu:18.04
RUN apt-get update && apt-get install openssl -y

WORKDIR /opt/threePP

COPY --from=three-phase-protocol-implementation_build-container /usr/local/lib/libcryptopp.a /usr/local/lib
#COPY --from=three-phase-protocol-implementation_build-container /usr/local/lib/libcryptopp.so /usr/local/lib

COPY --from=three-phase-protocol-implementation_build-container /home/threePP/dockerInstance .
COPY --from=three-phase-protocol-implementation_build-container /home/threePP/cert /opt/cert

CMD ["/bin/sh", "-c", "./dockerInstance 1 1 2 512"]
