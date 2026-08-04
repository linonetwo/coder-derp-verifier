FROM harbor.k3s.onetwo.website/docker-io/library/golang:1.24.5-alpine3.22 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN go mod tidy && \
    CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/coder-derp-verifier .

FROM harbor.k3s.onetwo.website/docker-io/library/alpine:3.22
COPY --from=build /out/coder-derp-verifier /coder-derp-verifier
USER 65532:65532
ENTRYPOINT ["/coder-derp-verifier"]
