# mikto — authorized-only recon & audit scanner
# сборка gcc в контейнере, рантайм минимальный

# ---------- stage 1: build ----------
FROM debian:12-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake libcurl4-openssl-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release -DMIKTO_BUILD_TESTS=OFF \
 && cmake --build build -j"$(nproc)" \
 && ./build/mikto --version

# ---------- stage 2: runtime ----------
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      libcurl4 libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m scanner

COPY --from=build /src/build/mikto /usr/local/bin/mikto

# отчёты пишем сюда; кэш внешних источников тоже
ENV HOME=/home/scanner
RUN mkdir -p /reports && chown -R scanner:scanner /reports /home/scanner
WORKDIR /reports
VOLUME ["/reports"]

USER scanner
ENTRYPOINT ["mikto"]
CMD ["--help"]

# примеры:
#   docker build -t mikto .
#   docker run --rm -v "$PWD:/reports" mikto scan https://target.example --html /reports/report.html
#   docker run --rm -v "$PWD:/reports" mikto scan http://127.0.0.1:8137 --json /reports/r.json
