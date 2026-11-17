FROM golang:1.27.4-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/netdiag-node ./cmd/netdiag-node
COPY internal/node ./internal/node
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/netdiag-node ./cmd/netdiag-node
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/netdiag-node /usr/local/bin/netdiag-node
COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/
EXPOSE 8443/tcp 8443/udp 4444/udp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/netdiag-node"]
