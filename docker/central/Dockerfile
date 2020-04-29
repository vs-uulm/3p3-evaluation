FROM alpine
RUN apk update && \
	apk add libgcc libstdc++ boost openssl

RUN apk add crypto++     --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing

WORKDIR /opt/threePP

COPY --from=three-phase-protocol-implementation_build-container /home/threePP/dockerAuthority .
COPY --from=three-phase-protocol-implementation_build-container /home/threePP/cert /opt/cert

CMD ["/bin/sh", "-c", "./dockerAuthority 6"]