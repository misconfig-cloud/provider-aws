FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o /out/misconfig-provider-aws .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.source="https://github.com/misconfig-cloud/provider-aws" \
      org.opencontainers.image.description="Misconfig governed-session AWS credential provider" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/misconfig-provider-aws /misconfig-provider-aws
USER 65532:65532
ENTRYPOINT ["/misconfig-provider-aws", "serve"]
