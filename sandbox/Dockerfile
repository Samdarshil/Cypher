# CYPHER sandbox image.
#
# Tool selection is adapted from verialabs/ctf-agent's sandbox (audited:
# their tool arsenal is REUSE-worthy even though their orchestration layer
# is not — see docs/audit.md). This image is what the ToolExecutor should
# run tools inside of once Docker-based isolation is wired up; today the
# executor already applies resource limits/timeouts directly, and this
# image adds filesystem/network isolation on top via `docker run`.
#
# Build:  docker build -f sandbox/Dockerfile -t cypher-sandbox .
# Run:    docker run --rm --network=none --memory=1g --cpus=1 \
#           -v <challenge_workspace>:/work:ro cypher-sandbox <tool> <args>

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    # General
    file binutils grep ripgrep xxd bsdmainutils python3 python3-pip \
    # Forensics
    exiftool binwalk foremost sleuthkit \
    # Steganography
    steghide imagemagick tesseract-ocr ruby ruby-dev \
    # Audio / media
    ffmpeg sox \
    # Reverse engineering
    radare2 gdb \
    # Web
    curl \
    && rm -rf /var/lib/apt/lists/*

# zsteg is a Ruby gem, not a pip package — installed separately, and
# deliberately NOT suppressed with '|| true': if this fails, the build
# must fail loudly rather than silently ship a broken sandbox image.
RUN gem install zsteg

# Python-based tools. No '|| true' here either — a failed install of any
# of these (e.g. pwntools, needed for the pwn category) must fail the
# build, not disappear silently and only surface later as a confusing
# runtime error during a competition.
RUN pip3 install --break-system-packages --no-cache-dir \
    pwntools \
    pycryptodome \
    gmpy2 \
    z3-solver \
    requests \
    volatility3

RUN useradd -m -u 1000 cypher
USER cypher
WORKDIR /work

ENTRYPOINT ["/bin/bash"]
