#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  Valkyrie OSINT Operating System — Bootstrap Script
#  Target: /opt/valkyrie/osint/
# ============================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

INSTALL_DIR="/opt/valkyrie/osint"

banner() {
    echo -e "${MAGENTA}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║          ██╗   ██╗ █████╗ ██╗     ██╗  ██╗                 ║"
    echo "║          ██║   ██║██╔══██╗██║     ██║ ██╔╝                 ║"
    echo "║          ██║   ██║███████║██║     █████╔╝                  ║"
    echo "║          ╚██╗ ██╔╝██╔══██║██║     ██╔═██╗                  ║"
    echo "║           ╚████╔╝ ██║  ██║███████╗██║  ██╗                 ║"
    echo "║            ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                 ║"
    echo "║                                                            ║"
    echo "║         OSINT Operating System — Phase 1 Bootstrap         ║"
    echo "║                                                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

info()    { echo -e "${CYAN}[INFO]${NC}  $1"; }
success() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $1"; exit 1; }

# ---- Pre-flight checks ----
check_prereqs() {
    info "Checking prerequisites..."

    if ! command -v docker &> /dev/null; then
        fail "Docker is not installed. Install Docker first: https://docs.docker.com/engine/install/"
    fi
    success "Docker found: $(docker --version)"

    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
        success "Docker Compose (plugin) found"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
        success "Docker Compose (standalone) found"
    else
        fail "Docker Compose is not installed."
    fi

    if ! docker info &> /dev/null 2>&1; then
        fail "Docker daemon is not running or current user lacks permission."
    fi
    success "Docker daemon is running"
}

# ---- Setup ----
setup_directory() {
    info "Setting up install directory: ${INSTALL_DIR}"

    if [ ! -d "${INSTALL_DIR}" ]; then
        mkdir -p "${INSTALL_DIR}"
        success "Created ${INSTALL_DIR}"
    else
        success "Directory exists: ${INSTALL_DIR}"
    fi

    # Copy project files if we're running from a different directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ "${SCRIPT_DIR}" != "${INSTALL_DIR}" ]; then
        info "Copying project files to ${INSTALL_DIR}..."
        cp -r "${SCRIPT_DIR}"/* "${INSTALL_DIR}/" 2>/dev/null || true
        cp -r "${SCRIPT_DIR}"/.env* "${INSTALL_DIR}/" 2>/dev/null || true
        cp -r "${SCRIPT_DIR}"/.gitignore "${INSTALL_DIR}/" 2>/dev/null || true
        success "Files copied to ${INSTALL_DIR}"
    fi
}

setup_env() {
    info "Checking environment file..."

    if [ ! -f "${INSTALL_DIR}/.env" ]; then
        cp "${INSTALL_DIR}/.env.example" "${INSTALL_DIR}/.env"
        warn ".env created from .env.example — edit it with your API keys!"
    else
        success ".env file exists"
    fi
}

# ---- Build & Deploy ----
deploy() {
    info "Pulling Docker images..."
    cd "${INSTALL_DIR}"
    ${COMPOSE_CMD} pull || warn "Some images may not have been pulled (build-only services)"

    info "Building and starting containers..."
    ${COMPOSE_CMD} up -d --build

    success "Containers started"
}

wait_for_api() {
    info "Waiting for API to initialize (10 seconds)..."
    sleep 10

    local retries=6
    local count=0
    while [ $count -lt $retries ]; do
        if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8400/health | grep -q "200"; then
            success "API is healthy!"
            return
        fi
        count=$((count + 1))
        info "Waiting for API... (attempt ${count}/${retries})"
        sleep 5
    done

    warn "API health check did not return 200 — it may still be starting up."
    warn "Check logs: ${COMPOSE_CMD} logs osint-api"
}

# ---- Status ----
print_status() {
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║                   SERVICE STATUS                             ║${NC}"
    echo -e "${BOLD}${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"

    cd "${INSTALL_DIR}"
    while IFS= read -r line; do
        echo -e "${CYAN}║${NC}  ${line}"
    done < <(${COMPOSE_CMD} ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || ${COMPOSE_CMD} ps)

    echo -e "${BOLD}${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}OSINT API:${NC}        http://127.0.0.1:8400"
    echo -e "${CYAN}║${NC}  ${BOLD}API Docs:${NC}         http://127.0.0.1:8400/docs"
    echo -e "${CYAN}║${NC}  ${BOLD}PhoneInfoga:${NC}      http://127.0.0.1:8401"
    echo -e "${CYAN}║${NC}  ${BOLD}Health Check:${NC}      http://127.0.0.1:8400/health"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

    echo ""
    echo -e "${YELLOW}${BOLD}NEXT STEPS:${NC}"
    echo -e "  1. Edit ${BOLD}${INSTALL_DIR}/.env${NC} with your API keys"
    echo -e "  2. Copy ${BOLD}${INSTALL_DIR}/nginx/osint.conf${NC} to /etc/nginx/sites-available/"
    echo -e "     and symlink to /etc/nginx/sites-enabled/"
    echo -e "  3. Update server_name in osint.conf with your domain"
    echo -e "  4. Run: ${BOLD}sudo nginx -t && sudo systemctl reload nginx${NC}"
    echo -e "  5. Access API docs at: ${BOLD}http://your-domain/docs${NC}"
    echo ""
}

# ---- Main ----
main() {
    banner
    check_prereqs
    setup_directory
    setup_env
    deploy
    wait_for_api
    print_status

    success "Valkyrie OSINT Operating System — Phase 1 deployment complete!"
}

main "$@"
