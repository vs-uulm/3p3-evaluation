FROM ubuntu:18.04
RUN apt-get update && apt-get install openssl -y

WORKDIR /opt/threePP
COPY --from=three-phase-protocol-implementation_build-container /home/threePP/dockerInstance .

#CMD ["/bin/sh", "-c", "mkdir -p /opt/cert \
#&& openssl genrsa -out ../cert/private.pem 4096 \
#&& openssl req -new -key ../cert/private.pem -out ../cert/signreq.csr -subj /C=DE \
#&& openssl x509 -req -days 365 -in ../cert/signreq.csr -signkey ../cert/private.pem -out ../cert/server_cert.pem \
#&& ./dockerInstance 0 1 2 512 100"]

CMD ["/bin/sh", "-c", "./dockerInstance 0 1 2 512 100"]
