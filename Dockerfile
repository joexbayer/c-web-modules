# Use the official Debian minimal image
FROM debian:latest

RUN apt-get update && apt-get install libssl-dev
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app
COPY . /app

CMD ["make", "run"]