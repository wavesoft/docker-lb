FROM golang:1.14-alpine
WORKDIR /build
COPY . /build
RUN go build

FROM haproxy:2.1-alpine
COPY --from=0 /build/docker-lb /usr/local/bin/docker-lb
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
ENTRYPOINT [ "/usr/local/bin/docker-lb" ]
