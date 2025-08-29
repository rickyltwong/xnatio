# Builder image: Ubuntu 20.04 to produce a PyInstaller onefile for Ubuntu 20 targets
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

# Base deps for Python build and PyInstaller
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      wget curl ca-certificates \
      zlib1g-dev libbz2-dev libssl-dev \
      libncurses5-dev libreadline-dev \
      libsqlite3-dev tk-dev \
      libgdbm-dev libdb-dev \
      libpcap-dev \
      libexpat1-dev libffi-dev \
      uuid-dev \
      xz-utils liblzma-dev \
      git pkg-config patchelf upx-ucl \
      file && \
    rm -rf /var/lib/apt/lists/*

# Install Python 3.13 from source (shared lib for PyInstaller)
ENV PYTHON_VERSION=3.13.1
RUN cd /tmp && \
    wget -q https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz && \
    tar -xzf Python-${PYTHON_VERSION}.tgz && \
    cd Python-${PYTHON_VERSION} && \
    ./configure \
      --enable-optimizations \
      --with-lto \
      --enable-shared \
      --with-ensurepip=install && \
    make -j"$(nproc)" && \
    make altinstall && \
    ln -sf /usr/local/bin/python3.13 /usr/local/bin/python3 && \
    ln -sf /usr/local/bin/pip3.13 /usr/local/bin/pip3 && \
    echo "/usr/local/lib" > /etc/ld.so.conf.d/python3.13.conf && \
    ldconfig && \
    cd / && rm -rf /tmp/Python-${PYTHON_VERSION}*

# Python tooling and runtime deps used by xnatio
RUN python3 -m pip install --upgrade pip setuptools wheel && \
    python3 -m pip install pyinstaller pyxnat python-dotenv requests lxml && \
    # Avoid pathlib backport which breaks PyInstaller on 3.13
    python3 -m pip uninstall -y pathlib || true

WORKDIR /app

# Copy project sources
COPY . /app

# Do NOT install the project; build from source tree to avoid reintroducing pathlib
# Create a simple entry that imports the CLI
RUN printf '#!/usr/bin/env python3\nfrom xnatio.cli import run_cli\nif __name__ == "__main__":\n    raise SystemExit(run_cli())\n' > /app/pyinstaller_entry.py

# Default command prints instructions; the host will override with a pyinstaller command
CMD echo "Run the builder like:" && \
    echo "  docker run --rm -e HOME=/tmp -u \\$(id -u):\\$(id -g) -v \\"$PWD/dist:/dist\\" xnatio:ubuntu20-builder \"bash -lc 'cd /app && pyinstaller --clean -y -n xnatio --onefile --distpath /dist --workpath /tmp/build --specpath /tmp/spec pyinstaller_entry.py'\"" && \
    ls -la /app 