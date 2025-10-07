FROM alpine:latest AS build

COPY run-vpn /usr/local/bin/run-vpn

RUN apk add --no-cache gcc make automake autoconf pkgconf git musl-dev openssl openssl-dev

WORKDIR /src

RUN git clone https://github.com/adrienverge/openfortivpn.git

WORKDIR /src/openfortivpn

RUN ./autogen.sh && \
    ./configure --prefix=/usr/local --sysconfdir=/etc && \
    make && \
    make install

# FROM busybox:latest

# COPY --from=build /usr/local/bin/openfortivpn /usr/local/bin/openfortivpn
# COPY --from=build /etc/openfortivpn /etc/openfortivpn