FROM alpine
RUN apk update && \
	apk add gcc g++ make cmake boost-dev boost openssl-dev openssl

RUN apk add crypto++     --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing
RUN apk add crypto++-dev --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing


RUN mkdir /home/threePP
WORKDIR /home/threePP

ADD ./src ./src
ADD ./cert ./cert
COPY ./CMakeLists.txt ./

RUN cmake . &&  make dockerInstance && make dockerAuthority


