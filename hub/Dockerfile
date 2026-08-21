# build: static, CGO-free
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dap-hub .

# runtime: debian-slim + curl for the /healthz check
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/dap-hub /usr/local/bin/dap-hub
RUN mkdir -p /data && chown -R nobody:nogroup /data
USER nobody
ENV HUB_ADDR=:8080 HUB_CHANNELS_FILE=/data/channels.json
EXPOSE 8080
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["dap-hub"]
