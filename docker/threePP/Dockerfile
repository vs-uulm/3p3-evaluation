FROM ubuntu:18.04
RUN apt-get update && apt-get install openssl iproute2 -y

WORKDIR /opt/threePP
COPY --from=three-phase-protocol-implementation_build-container /home/threePP/dockerInstance .

#CMD ["/bin/sh", "-c", "mkdir -p /opt/cert \
#&& openssl genrsa -out ../cert/private.pem 4096 \
#&& openssl req -new -key ../cert/private.pem -out ../cert/signreq.csr -subj /C=DE \
#&& openssl x509 -req -days 365 -in ../cert/signreq.csr -signkey ../cert/private.pem -out ../cert/server_cert.pem \
#&& ./dockerInstance 0 1 2 512 100"]

# 100ms delay
#tc qdisc add dev eth0 root netem delay 100ms
# 100+-10ms delay with 25% correlation
#tc qdisc add dev eth0 root netem delay 100ms 10ms 25%

#tbf: use the token bucket filter to manipulate traffic rates
#rate sustained max rate
#burst maximum allowed burst
#latency packets with higher latency get dropped
#tc qdisc add dev eth0 root tbf rate 50mbit burst 100kb latency 1000ms

CMD tc qdisc add dev eth0 root netem delay 100ms 10ms 25% \
&& tc qdisc add dev eth0 root tbf rate 50mbit burst 100kb latency 1000ms \
&& ./dockerInstance 0 1 2 512 0

# parameters: 0 1 2 512 100
# 0 -> unsecured (1-> secured?)
# 1 -> #thread for commitments
# 2 -> #senders
# 512 -> message size
# 100 -> delay in ms
#CMD ["/bin/sh", "-c", "./dockerInstance 0 1 2 512 100"]
