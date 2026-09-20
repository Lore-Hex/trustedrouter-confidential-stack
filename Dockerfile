# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.23 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.1.0
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -buildid= -X main.version=$VERSION" -o /out/trcs ./cmd/trcs && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -buildid=" -o /out/trcs-helm-test ./cmd/trcs-helm-test
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/trcs /trcs
COPY --from=build /out/trcs-helm-test /trcs-helm-test
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/trcs"]
CMD ["shim"]
