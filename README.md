# NetDog

> **Advanced Network Security Scanner & Monitoring Platform**

A comprehensive network reconnaissance and security assessment tool built with modern web technologies. NetDog combines powerful scanning capabilities with an intuitive interface for network discovery, vulnerability assessment, and device monitoring.

<div align="center">

![NetDog Dashboard](https://img.shields.io/badge/Status-Active-green.svg)
![Version](https://img.shields.io/badge/Version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

</div>

---

## Features

<table>
<tr>
<td>

### **Network Discovery**
- **Fast Host Discovery** - Comprehensive TCP/UDP/ICMP probing
- **Device Fingerprinting** - OS detection and device classification  
- **Real-time Scanning** - Live progress with animated UI updates
- **Multi-target Support** - CIDR ranges, hostnames, IP lists

</td>
<td>

### **Security Assessment**
- **Vulnerability Scanning** - CVE lookup with CVSS scoring
- **Port Analysis** - Service detection and version identification
- **Risk Scoring** - Automated threat assessment
- **Compliance Reporting** - Export scan results

</td>
</tr>
<tr>
<td>

### **Device Management**
- **Asset Inventory** - Automatic device categorization
- **Vendor Detection** - MAC address vendor lookup
- **Service Mapping** - Open ports and running services
- **Historical Tracking** - Device changes over time

</td>
<td>

### **Network Utilities**
- **Speed Testing** - Bandwidth measurement
- **Connectivity Testing** - Ping, traceroute, DNS lookup  
- **Traffic Analysis** - Network disruption testing
- **Custom Tools** - Extensible utility framework

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

- **Docker** & **Docker Compose** - Container orchestration
- **Git** - Version control
- **Root/Admin Access** - Required for advanced scanning features

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/John0n1/netdog.git
   cd netdog
   ```

2. **Launch with Docker**
   ```bash
   chmod +x setup.sh
   sudo ./setup.sh
   ```

3. **Access the application**
   - **Web Interface**: http://localhost:5173
   - **API Documentation**: http://localhost:8000/docs

### First Scan

1. Open NetDog in your browser
2. Click **"New Scan"** 
3. Select your network (auto-detected) or enter targets
4. Choose scan intensity level
5. Click **"Start Scan"** and watch devices appear in real-time!

---

## Scan Modes

<div align="center">

| Mode | Description | Use Case | Speed |
|------|-------------|----------|-------|
| **Slow** | Stealthy, 50 ports + OS detection | External/Production | ★ |
| **Stealthy** | Quiet, 200 ports + OS detection | Authorized Pentest | ★★ |
| **Medium** | Service detection, 1000 ports | Standard Assessment | ★★★ |
| **Normal** | Full TCP + OS fingerprint | Internal Networks | ★★★★ |
| **Aggressive** | TCP/UDP + Scripts | Deep Analysis | ★★★★★ |
| **Offensive** | Vulnerability + Auth testing | Red Team Ops | ★★★★★ |
| **Intrusive** | Full exploitation attempts | Authorized Only | ★★★★★ |

</div>

---

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   React + Vite  │────│   FastAPI + DB   │────│  Celery Workers │
│   (Frontend)    │    │    (Backend)     │    │   (Scanning)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                         ┌─────────────────┐
                         │ Redis + Postgres│
                         │  (Data Layer)   │
                         └─────────────────┘
```

### Tech Stack

- **Frontend**: React 18, Vite, Tailwind CSS, React Query
- **Backend**: FastAPI, SQLAlchemy, PostgreSQL, Redis  
- **Scanning**: Nmap, Python-nmap, Custom algorithms
- **Queue**: Celery with Redis broker
- **Infrastructure**: Docker, Docker Compose

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Database
POSTGRES_DB=netdog
POSTGRES_USER=netdog
POSTGRES_PASSWORD=your_secure_password

# Redis
REDIS_URL=redis://redis:6379/0

# API
SECRET_KEY=your_jwt_secret_key
API_HOST=0.0.0.0
API_PORT=8000

# Scanning
SCAN_TIMEOUT=3600
MAX_CONCURRENT_SCANS=5
CVE_CACHE_TTL=86400
```

### Development Setup

#### Backend Development
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Frontend Development
```bash
cd frontend
npm install
npm run dev
```

---

## API Reference

### Authentication
```bash
# Login and get JWT token
curl -X POST http://localhost:8000/api/v1/auth/token \
  -d "username=admin&password=admin"
```

### Start Scan
```bash
# Launch network scan
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.0/24"],
    "mode": "normal",
    "consent": {"approved": true, "by": "user"}
  }'
```

### Get Results
```bash
# Retrieve scan results
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/devices?scan_id=$SCAN_ID
```

---

## Security & Legal

### **Important Legal Notice**

NetDog is designed for **authorized security testing only**. Users must:

- **Own the target network** or have **explicit written permission**
- **Comply with local laws** and regulations
- **Use responsibly** for legitimate security assessment
- **Never scan networks without authorization**

### Security Features

- **JWT Authentication** - Secure API access
- **Input Validation** - SQL injection prevention  
- **Rate Limiting** - DDoS protection
- **Audit Logging** - Complete activity tracking
- **Consent Tracking** - Legal compliance documentation

---

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Commands

```bash
# Start development containers
sudo docker compose up -d

# View logs
sudo docker compose logs -f

# Run tests
docker compose exec backend pytest
cd frontend && npm test

# Stop services
sudo docker compose down
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made for the cybersecurity community**

[Star this repo](https://github.com/John0n1/netdog) | [Report Bug](https://github.com/John0n1/netdog/issues) | [Request Feature](https://github.com/John0n1/netdog/discussions)

</div>
