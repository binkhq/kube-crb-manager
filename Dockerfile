FROM --platform=$BUILDPLATFORM golang:1.18-alpine3.15 AS build

RUN apk update && apk add --no-cache git ca-certificates && \
    update-ca-certificates

WORKDIR /go/src/github.com/binkhq/kube-crb-manager
COPY . .

RUN go mod download
RUN go mod verify

ARG TARGETOS
ARG TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build -ldflags="-w -s" -o /kube-crb-manager .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /kube-crb-manager /kube-crb-manager
ENTRYPOINT ["/kube-crb-manager"]
