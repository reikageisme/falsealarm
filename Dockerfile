FROM python:3.11-slim AS builder

# Install Go compiler and build dependencies
RUN apt-get update && apt-get install -y \
    golang \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the go engine source
COPY engine-go/ ./engine-go/

# Build the Go engine
WORKDIR /app/engine-go
RUN go build -o dirfuzz-engine dirfuzz.go

# Final stage
FROM python:3.11-slim

WORKDIR /app

# Copy the built Go engine
COPY --from=builder /app/engine-go/dirfuzz-engine /app/engine-go/dirfuzz-engine

# Copy Python requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Install the Python package in editable mode
RUN pip install -e .

ENTRYPOINT ["python", "-m", "falsealarm"]
CMD ["--help"]
