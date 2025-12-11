# Build stage
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
ARG BUILD_VERSION=dev
RUN go build -ldflags "-X main.buildVersion=${BUILD_VERSION}" -o /out/arouter ./cmd/controller

# Runtime stage
FROM alpine:3.23
WORKDIR /app

COPY --from=build /out/arouter /app/arouter

RUN mkdir -p /app/web
COPY --from=build /src/web/dist /app/web/dist
RUN chmod +x /app/arouter
# Optional: default to SQLite db in /app/data/arouter.db
RUN mkdir -p /app/data
ENV DB_PATH=/app/data/arouter.db
ENV WEB_DIST=/app/web/dist
ENV CONTROLLER_ADDR=:8080
EXPOSE 8080
CMD ["/app/arouter"]
