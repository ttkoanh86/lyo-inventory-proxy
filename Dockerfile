# Base image with Go
FROM golang:1.24.5-bookworm

# Install Valkey server
RUN apt-get update && apt-get install -y \
    curl build-essential pkg-config libssl-dev \
 && curl -fsSL https://github.com/valkey-io/valkey/archive/refs/tags/7.2.5.tar.gz | tar xz \
 && cd valkey-7.2.5 && make && make install \
 && cd .. && rm -rf valkey-7.2.5 \
 && apt-get remove --purge -y curl build-essential pkg-config libssl-dev \
 && apt-get autoremove -y && apt-get clean

# Set working directory
WORKDIR /app

# Copy go mod and sum files first
COPY go.mod go.sum ./

# Download Go module dependencies
RUN go mod download

# Copy the rest of the app source code
COPY . .

# Build the Go (Gin) app
RUN go build -o server .

# Expose only the Gin server port
EXPOSE 8080

# Start Valkey and the Gin server in parallel
CMD ["sh", "-c", "valkey-server ./valkey.conf && ./server"]
