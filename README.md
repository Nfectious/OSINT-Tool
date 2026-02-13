# Valkyrie OSINT Operating System

![Python 3.11](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-Compose-blue?logo=docker)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?logo=postgresql)

Automated OSINT intelligence gathering and analysis platform. Aggregate data from multiple open-source intelligence tools, store structured findings, and generate AI-powered pattern analysis using local LLMs via Ollama.

## Quick Start

```bash
# 1. Clone / copy to your server
git clone <repo-url> /opt/valkyrie/osint
cd /opt/valkyrie/osint

# 2. Configure environment
cp .env.example .env
nano .env   # Add your API keys

# 3. Deploy
chmod +x bootstrap.sh
./bootstrap.sh
```

The API will be available at `http://127.0.0.1:8400` with interactive docs at `/docs`.

## API Endpoints

### Projects

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/projects` | Create a new project |
| `GET` | `/api/v1/projects` | List all projects |
| `GET` | `/api/v1/projects/{id}` | Get project with entity/pattern counts |
| `PUT` | `/api/v1/projects/{id}` | Update project |
| `DELETE` | `/api/v1/projects/{id}` | Archive project (soft delete) |
| `POST` | `/api/v1/projects/{id}/run` | Run OSINT tools on all entities |
| `POST` | `/api/v1/projects/{id}/analyze` | Run LLM pattern analysis |
| `GET` | `/api/v1/projects/{id}/report` | Full project report |

### Entities

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/projects/{id}/entities` | Add entity to project |
| `GET` | `/api/v1/projects/{id}/entities` | List entities for project |
| `GET` | `/api/v1/projects/{id}/entities/{eid}` | Get entity with findings |
| `DELETE` | `/api/v1/projects/{id}/entities/{eid}` | Remove entity |
| `POST` | `/api/v1/projects/{id}/entities/{eid}/run` | Run OSINT on single entity |

### Findings

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/entities/{eid}/findings` | List findings for entity |
| `GET` | `/api/v1/findings/{id}` | Get finding with full raw data |

### Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/projects/{id}/analyze` | Run LLM analysis |
| `GET` | `/api/v1/projects/{id}/patterns` | List patterns for project |
| `GET` | `/api/v1/projects/{id}/summary` | AI-generated project summary |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/` | System info |

## Entity Types

| Type | Description | Example |
|------|-------------|---------|
| `phone` | Phone number | +1234567890 |
| `email` | Email address | user@example.com |
| `username` | Social media username | johndoe |
| `domain` | Domain name | example.com |
| `ip` | IP address | 192.168.1.1 |
| `name` | Person name | John Doe |
| `social` | Social media URL | https://twitter.com/user |
| `file` | File path for analysis | /app/data/photo.jpg |

## Tools Integration

| Tool | Category | Entity Types | Source |
|------|----------|-------------|--------|
| PhoneInfoga | Phone | phone | REST API (containerized) |
| NumVerify | Phone | phone | numverify.com API |
| Holehe | Email | email | CLI subprocess |
| Have I Been Pwned | Email | email | HIBP API v3 |
| Sherlock | Username | username | CLI subprocess |
| WHOIS | Network | domain, ip | python-whois library |
| DNS Enumeration | Network | domain | dnspython library |
| VirusTotal | Network | domain, file | VirusTotal API v3 |
| ExifTool | General | file | CLI subprocess |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_DB` | `osint` | Database name |
| `POSTGRES_USER` | `valkyrie` | Database user |
| `POSTGRES_PASSWORD` | `changeme` | Database password |
| `DATABASE_URL` | `postgresql://valkyrie:changeme@osint-db:5432/osint` | Full DB connection string |
| `NUMVERIFY_API_KEY` | | NumVerify API key |
| `HIBP_API_KEY` | | Have I Been Pwned API key |
| `SHODAN_API_KEY` | | Shodan API key |
| `VIRUSTOTAL_API_KEY` | | VirusTotal API key |
| `OLLAMA_BASE_URL` | `http://host.docker.internal:11434` | Ollama endpoint |
| `OLLAMA_MODEL` | `mistral` | LLM model for analysis |
| `PHONEINFOGA_URL` | `http://phoneinfoga:8080` | PhoneInfoga service URL |
| `API_PORT` | `8400` | API listen port |
| `DEBUG` | `false` | Debug mode |

## Server Integration (Contabo VPS)

This platform is designed to coexist with existing services:

| Service | Port | Status |
|---------|------|--------|
| Nginx | 80/443 | Existing — add osint.conf |
| n8n | 5678 | Existing |
| OpenWebUI | 3000 | Existing |
| Ollama | 11434 | Existing — used for LLM analysis |
| OSINT API | 8400 | New |
| PhoneInfoga | 8401 | New |

### Nginx Setup

1. Copy `nginx/osint.conf` to `/etc/nginx/sites-available/osint`
2. Symlink: `ln -s /etc/nginx/sites-available/osint /etc/nginx/sites-enabled/`
3. Update `server_name` with your domain
4. Test and reload: `sudo nginx -t && sudo systemctl reload nginx`

### Ollama Integration

The LLM analyzer connects to your existing Ollama instance. Inside Docker containers, use `http://host.docker.internal:11434`. If that doesn't resolve, set `OLLAMA_BASE_URL` to your server's private IP.

## Adding New Tools

1. Create a new file in `backend/tools/<category>/`
2. Extend `BaseTool`:

```python
from tools.base_tool import BaseTool

class MyTool(BaseTool):
    @property
    def name(self) -> str:
        return "MyTool"

    @property
    def category(self) -> str:
        return "network"

    def run(self, entity_value: str) -> dict:
        # Your tool logic here
        return self._make_finding(
            raw_data={"result": "data"},
            summary="What was found",
            severity="info",
            tags=["network", "mytool"],
        )
```

3. Register in `backend/services/tool_dispatcher.py` by adding to `ENTITY_TOOL_MAP`

## Directory Structure

```
valkyrie-osint/
├── README.md
├── .env.example
├── .gitignore
├── docker-compose.yml
├── bootstrap.sh
├── nginx/
│   └── osint.conf
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── project.py
│   │   ├── entity.py
│   │   ├── finding.py
│   │   └── pattern.py
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── projects.py
│   │   ├── entities.py
│   │   ├── findings.py
│   │   └── analysis.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── osint_runner.py
│   │   ├── tool_dispatcher.py
│   │   └── llm_analyzer.py
│   └── tools/
│       ├── __init__.py
│       ├── base_tool.py
│       ├── phone/
│       │   ├── __init__.py
│       │   ├── phoneinfoga.py
│       │   └── numverify.py
│       ├── email/
│       │   ├── __init__.py
│       │   ├── holehe.py
│       │   └── hibp.py
│       ├── username/
│       │   ├── __init__.py
│       │   └── sherlock.py
│       ├── network/
│       │   ├── __init__.py
│       │   ├── whois_tool.py
│       │   ├── dnsdumpster.py
│       │   └── virustotal.py
│       └── general/
│           ├── __init__.py
│           └── exiftool.py
└── data/
    └── .gitkeep
```
