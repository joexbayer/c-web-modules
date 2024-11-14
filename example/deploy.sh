#!/bin/bash

DEFAULT_CONFIG_FILE="routes.ini"
GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; BLUE="\033[1;34m"; NC="\033[0m"

deploy_module() {
    local code="$1" server_url="$2" response
    echo -e "${BLUE}→ Deploying ${YELLOW}$code${NC} to ${YELLOW}$server_url${NC}..."
    response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$server_url" -F "code=@$code")
    [[ "$response" == "200" ]] && echo -e "${GREEN}✔ Deployment succeeded${NC}\n" || echo -e "${RED}✖ Deployment failed (HTTP $response)${NC}\n"
}

deploy_from_config() {
    local config_file="$1" server_url modules
    [[ ! -f "$config_file" ]] && echo -e "${RED}Error: Config file $config_file not found${NC}" && return 1

    server_url=$(awk -F= '/^server_url=/{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$config_file")
    [[ -z "$server_url" ]] && echo -e "${RED}Error: server_url not in config${NC}" && return 1
    echo -e "${GREEN}🌐 Deploying to server: ${YELLOW}$server_url${NC}\n"

    # Parse module files from the [modules] section
    modules=$(awk '/^\[modules\]/{flag=1; next} /^\[/{flag=0} flag && NF' "$config_file")
    for code in $modules; do
        [[ -f "$code" ]] && deploy_module "$code" "$server_url" || echo -e "${YELLOW}⚠ Skipping missing file: $code${NC}"
    done
}

main() {
    local command="$1" file="$2" server_url

    case "$command" in
        deploy)
            server_url=$(awk -F= '/^server_url=/{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$DEFAULT_CONFIG_FILE")
            [[ -z "$server_url" ]] && echo -e "${RED}Error: server_url not in config${NC}" && return 1

            if [[ -n "$file" ]]; then
                [[ -f "$file" ]] && deploy_module "$file" "$server_url" || echo -e "${RED}Error: File $file not found${NC}"
            else
                echo -e "${GREEN}📄 Using config file: ${YELLOW}$DEFAULT_CONFIG_FILE${NC}\n"
                deploy_from_config "$DEFAULT_CONFIG_FILE"
            fi
            ;;
        *) echo -e "${YELLOW}Usage: $0 deploy [file.c]${NC}" ;;
    esac
}

main "$@"
