FROM golang:1.22 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /corso ./cmd/corso/
RUN CGO_ENABLED=0 go build -o /corsoctl ./cmd/corsoctl/

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /corso /corso
COPY --from=builder /corsoctl /corsoctl
USER 65534:65534
ENTRYPOINT ["/corso"]
