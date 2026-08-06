# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.26.5

FROM golang:${GO_VERSION}-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w" -o /out/auth-api ./cmd/api

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w" -o /out/migrate ./cmd/migrate

FROM busybox:1.38.0-uclibc@sha256:297dda192bda2157ddf40abb47a45a1090caff1864db9cfb9ce4b901ba318a3c AS busybox

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
COPY --from=build /out/auth-api /auth-api
COPY --from=build /out/migrate /migrate
COPY --from=busybox /bin/busybox /busybox
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/auth-api"]
