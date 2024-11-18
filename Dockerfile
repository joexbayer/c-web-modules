# Use the official Debian minimal image
FROM ubuntu:latest

# Install necessary packages
RUN apt-get update && apt-get install -y \
    libssl-dev \
    libsqlite3-dev \
    libjansson-dev \
    make \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
EXPOSE 8080

RUN make

CMD ["./bin/cweb"]
