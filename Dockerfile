# syntax=docker/dockerfile:1.7

ARG OTEL_COLLECTOR_VERSION=0.156.0
ARG OTEL_COLLECTOR_DIGEST=sha256:125bdbeb7590cc1952c5b3430ecf14063568980c2c93d5b38676cc0446ed8108

FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS ui
WORKDIR /ui
COPY ui/package*.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci
COPY ui/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
COPY --from=ui /ui/dist/ ./cmd/server/web/
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /server ./cmd/server

FROM --platform=$TARGETPLATFORM otel/opentelemetry-collector-contrib:${OTEL_COLLECTOR_VERSION}@${OTEL_COLLECTOR_DIGEST} AS collector

FROM gcr.io/distroless/static-debian12:nonroot@sha256:aef9602f8710ec12bde19d593fed1f76c708531bb7aba205110f1029786ead7b
COPY --from=build --chmod=0555 /server /server
COPY --from=collector --chmod=0555 /otelcol-contrib /otelcol-contrib
ARG OTEL_COLLECTOR_VERSION
ENV COLLECTOR_VALIDATOR_VERSION=${OTEL_COLLECTOR_VERSION}
USER 65532:65532
EXPOSE 8080 4320
ENTRYPOINT ["/server"]
