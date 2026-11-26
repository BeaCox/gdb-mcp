FROM python:3.12-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        binutils \
        gdb \
        gdbserver \
    && (DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends rr || true) \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md MANIFEST.in ./
COPY src ./src

RUN pip install --no-cache-dir .

ENTRYPOINT ["gdb-mcp"]
