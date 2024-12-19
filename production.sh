#!/bin/bash

CERT_FILE="server.crt"
KEY_FILE="server.key"
DOCKER_FLAG=false

# Parse command line options
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --docker)
            DOCKER_FLAG=true
            ;;
        *)
            echo "Invalid option: $1" >&2
            exit 1
            ;;
    esac
    shift
done

# Check if server.crt and server.key exist
if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
        echo "Certificate or key file not found."
        read -p "Do you want to generate them? (y/n): " generate

        if [[ "$generate" == "y" || "$generate" == "Y" ]]; then
                # Generate server.crt and server.key
                openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes
                echo "Certificate and key generated."
        else
                echo "Certificate and key not generated. Exiting."
                exit 1
        fi
fi

# If docker flag is given
if [ "$DOCKER_FLAG" = true ]; then
        docker build --build-arg PRODUCTION=1 -t cweb:production .
else
        # Run make with -DPRODUCTION
        make clean
        make PRODUCTION=1
fi