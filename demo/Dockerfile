FROM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /tokening ./cmd/tokening
FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /tokening /usr/local/bin/tokening
WORKDIR /state
ENTRYPOINT []
CMD ["tokening", "version"]
