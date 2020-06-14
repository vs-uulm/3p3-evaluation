FROM ubuntu:18.04
RUN apt-get update && apt-get install openssl -y

WORKDIR /opt/threePP

COPY --from=three-phase-protocol-implementation_build-container /home/threePP/dockerAuthority .
COPY --from=three-phase-protocol-implementation_build-container /home/threePP/cert /opt/cert

CMD ["/bin/sh", "-c", "./dockerAuthority 6"]