FROM golang:1.22 AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/server ./cmd/server

FROM gcr.io/distroless/static-debian12
WORKDIR /app
COPY --from=build /app/server /app/server
COPY templates /app/templates
COPY static /app/static
COPY db/migrations /app/db/migrations
ENV APP_ADDR=:8080
ENV APP_TLS=false
EXPOSE 8080
ENTRYPOINT ["/app/server"]
