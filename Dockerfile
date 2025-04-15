# Use the official Debian minimal image
FROM debian:latest

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

# Define a build argument for production
ARG PRODUCTION=0

# Run make with the appropriate flags based on the PRODUCTION argument
RUN if [ "$PRODUCTION" -eq 1 ]; then make clean && make PRODUCTION=1; else make clean && make; fi


CMD ["./bin/cweb"]
