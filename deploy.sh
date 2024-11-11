#!/bin/bash

DEFAULT_CONFIG_FILE="routes.txt"

# Color codes for fancy output
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BLUE="\033[1;34m"
NC="\033[0m" # No color

deploy_route() {
    local route="$1" function_name="$2" code="$3" server_url="$4" method="${5:-POST}" libs="$6"
    echo -e "${BLUE}→ Deploying ${YELLOW}$function_name${NC} to route ${YELLOW}$route${NC} using method ${GREEN}$method${NC}..."

    response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$server_url" -H "Content-Type: multipart/form-data" \
        -F "route=$route" -F "function_name=$function_name" -F "code=@$code" \
        -F "method=$method" ${libs:+-F "libs=$libs"})

    if [[ "$response" == "200" ]]; then
        echo -e "${GREEN}✔ Deployment succeeded${NC}\n"
    else
        echo -e "${RED}✖ Deployment failed (HTTP $response)${NC}\n"
    fi
}

deploy_routes_from_config() {
    local config_file="$1" server_url=""
    [[ ! -f "$config_file" ]] && echo -e "${RED}Error: Configuration file not found: $config_file${NC}" && return 1

    # Parse server URL and ignore it in subsequent parsing
    server_url=$(awk -F= '/^server_url=/{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$config_file")
    [[ -z "$server_url" ]] && echo -e "${RED}Error: server_url not found in the config file.${NC}" && return 1
    echo -e "${GREEN}🌐 Deploying to server: ${YELLOW}$server_url${NC}\n"

    # Parse route entries
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^#|^$|^server_url= ]] && continue
        route=$(echo "$line" | sed -n 's/.*route=\([^ ]*\).*/\1/p')
        function_name=$(echo "$line" | sed -n 's/.*function_name=\([^ ]*\).*/\1/p')
        code=$(echo "$line" | sed -n 's/.*code=\([^ ]*\).*/\1/p')
        method=$(echo "$line" | sed -n 's/.*method=\([^ ]*\).*/\1/p')
        libs=$(echo "$line" | sed -n 's/.*libs=\([^ ]*\).*/\1/p')

        [[ -z "$route" || -z "$function_name" || -z "$code" ]] && echo -e "${YELLOW}⚠ Skipping invalid line: $line${NC}" && continue
        deploy_route "$route" "$function_name" "$code" "$server_url" "$method" "$libs"
    done < "$config_file"
}

main() {
    local config_file="${1:-$DEFAULT_CONFIG_FILE}"
    echo -e "${GREEN}📄 Using configuration file: ${YELLOW}$config_file${NC}\n"
    deploy_routes_from_config "$config_file"
}

main "$@"