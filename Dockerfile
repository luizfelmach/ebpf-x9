FROM ubuntu:24.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    clang \
    gcc \
    llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/x9.bpf.c src/x9.c ./

RUN mkdir -p /app/bin && \
    clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c x9.bpf.c -o /app/bin/x9.bpf.o && \
    gcc -O2 -g x9.c -o /app/bin/x9 -lbpf -lelf -lz

CMD ["/app/bin/x9", "eth0", "/var/log/x9/events.ndjson", "/app/bin/x9.bpf.o"]
