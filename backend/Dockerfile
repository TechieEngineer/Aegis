FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.* ./
RUN go mod download
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aegis .
FROM alpine:3.24
RUN apk add --no-cache ca-certificates && addgroup -S aegis && adduser -S -G aegis aegis
COPY --from=build /out/aegis /usr/local/bin/aegis
USER aegis
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aegis"]
