FROM ubuntu:18.04
RUN apt-get update && apt-get install openssl -y

WORKDIR /opt/cert
RUN openssl genrsa -out private.pem 4096
RUN openssl req -new -key private.pem -out signreq.csr -subj "/C=DE"
RUN openssl x509 -req -days 365 -in signreq.csr -signkey private.pem -out server_cert.pem

WORKDIR /opt/threePP
COPY --from=three-phase-protocol-implementation_build-container /home/threePP/dockerAuthority .
CMD ./dockerAuthority $nodes
