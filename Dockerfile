FROM golang:alpine AS build

RUN apk update && apk add --no-cache git ca-certificates && update-ca-certificates

WORKDIR /go/src/git.bink.com/tools/blobfileexporter
COPY . .

RUN go mod download
RUN go mod verify
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /a .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /a /a
ENTRYPOINT ["/a"]