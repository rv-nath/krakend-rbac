# Stage 1: Build the plugin
FROM golang:1.22.7-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy the Go source code to the container
COPY . .

# Install musl-dev and gcc for cgo compilation
RUN apk add --no-cache musl-dev gcc

# Enable CGO for building the plugin
ENV CGO_ENABLED=1

# Build the plugin using the same Go version as KrakenD, in plugin mode
RUN go build -buildmode=plugin -o krakend-rback.so

# Stage 2: Create the final KrakenD image
FROM devopsfaith/krakend:latest

# Copy the plugin from the build stage to the correct directory
COPY --from=builder /app/krakend-rback.so /opt/krakend/plugins/

# Copy the KrakenD configuration file to /etc/krakend/
COPY ./krakend.json /etc/krakend/krakend.json
RUN chmod 644 /etc/krakend/krakend.json

# Set the entrypoint to start KrakenD
ENTRYPOINT ["/usr/bin/krakend", "run", "-c", "/etc/krakend/krakend.json"]

