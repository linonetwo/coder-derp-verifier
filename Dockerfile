FROM golang:1.26.5-alpine3.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/coder-derp-verifier .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/coder-derp-verifier /coder-derp-verifier
USER 65532:65532
ENTRYPOINT ["/coder-derp-verifier"]
