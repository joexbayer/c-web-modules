#!/bin/bash

DEFAULT_CONFIG_FILE="routes.txt"

deploy_route() {
    local route="$1"
    local function_name="$2"
    local code="$3"
    local server_url="$4"

    echo "Deploying $function_name to $route"

    curl -X POST "$server_url" -H "Content-Type: multipart/form-data" -F "route=$route" -F "function_name=$function_name" -F "code=@$code"
    echo -e "\n"
}

deploy_routes_from_config() {
    local config_file="$1"
    local server_url=""

    if [[ ! -f "$config_file" ]]; then
        echo "Error: Configuration file not found: $config_file"
        return 1
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "$line" ]] && continue
        if [[ "$line" =~ ^server_url= ]]; then
            server_url=$(echo "$line" | cut -d '=' -f2 | tr -d '\r' | xargs)
            echo "Parsed Server URL: '$server_url'"  # Debugging line to confirm URL format
            break
        fi
    done < "$config_file"

    if [[ -z "$server_url" ]]; then
        echo "Error: server_url not found in the config file."
        return 1
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^server_url= ]] && continue

        local route=$(echo "$line" | grep -oP 'route=\K[^ ]+')
        local function_name=$(echo "$line" | grep -oP 'function_name=\K[^ ]+')
        local code=$(echo "$line" | grep -oP 'code=\K[^ ]+')

        if [[ -z "$route" || -z "$function_name" || -z "$code" ]]; then
            echo "Warning: Skipping invalid line: $line"
            continue
        fi
        echo 
        deploy_route "$route" "$function_name" "$code" "$server_url"
    done < "$config_file"
}

main() {
    local config_file="${1:-$DEFAULT_CONFIG_FILE}"
    echo "Using configuration file: $config_file"
    deploy_routes_from_config "$config_file"
}

main "$@"
