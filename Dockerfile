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
COPY src/x9.bpf.c src/x9.c src/x9.h ./

RUN mkdir -p /app/bin && \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then BPF_ARCH=x86; elif [ "$ARCH" = "aarch64" ]; then BPF_ARCH=arm64; else BPF_ARCH=$ARCH; fi && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_${BPF_ARCH} -I/usr/include/$ARCH-linux-gnu -c x9.bpf.c -o /app/bin/x9.bpf.o && \
    gcc -O2 -g x9.c -o /app/bin/x9 -lbpf -lelf -lz

CMD ["/app/bin/x9", "/var/log/x9/events.csv", "/app/bin/x9.bpf.o"]
