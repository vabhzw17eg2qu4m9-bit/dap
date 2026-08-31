# build: static, CGO-free
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/dap-hub .
RUN mkdir -p /out/data

# runtime: distroless static nonroot (uid 65532; bundles ca-certificates + tzdata).
# No shell/curl here — health probing is done by the platform (Cloud Run/k8s/ECS HTTP probes on /healthz).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/dap-hub /usr/local/bin/dap-hub
COPY --from=build --chown=65532:65532 /out/data /data
USER nonroot
ENV HUB_ADDR=:8080 HUB_CHANNELS_FILE=/data/channels.json
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["dap-hub"]
