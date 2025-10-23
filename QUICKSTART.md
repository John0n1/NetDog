# NetDog - Quick Start Guide

## Prerequisites

- Docker & Docker Compose
- At least 2GB free RAM
- Network access for scanning

## Installation

1. **Clone or navigate to the project directory**

```bash
cd /home/john/netdog
```

2. **Run the setup script**

```bash
./setup.sh
```

This will:
- Create `.env` file with a secure secret key
- Build Docker images
- Start all services (API, Worker, Frontend, Database, Redis)

3. **Access the application**

Open your browser to: **http://localhost:5173**

## First Steps

### 1. Register an Account

- Click "Register" on the login page
- Create your admin account
- You'll be automatically logged in

### 2. Start Your First Scan

- Click "New Scan" button
- Enter target IPs or networks (e.g., `192.168.1.0/24`)
- Choose scan mode (Normal recommended for first scan)
- Fill in consent information
- Check the authorization checkbox
- Click "Start Scan"

### 3. Monitor Progress

- Watch the console pane for live logs
- Status badges show active scans and vulnerabilities
- Scan list updates automatically

### 4. View Results

- Go to "Devices" tab to see discovered hosts
- Go to "Vulnerabilities" tab to see CVEs
- Click on any device or vulnerability for details

## Tips

- **Scan Modes:**
  - **Slow**: Stealthy sweep of the top 50 ports with intentional delays
  - **Medium**: Service detection against the top 100 ports
  - **Normal**: Full TCP scan with OS fingerprinting (recommended)
  - **Aggressive**: Full TCP + UDP coverage with discovery scripts (loud)

- **Consent is Required**: All intrusive operations require explicit consent for legal/audit purposes

- **Live Updates**: Keep the console pane open to see real-time scan progress

- **Risk Scores**: Higher scores indicate more open ports and vulnerabilities

## Network Utilities

The **NetUtil** tab provides:
- **Ping**: Test connectivity to hosts
- **Speed Test**: Measure internet connection speed
- **DNS Lookup**: Resolve hostnames to IPs

## Stopping the Application

```bash
docker-compose down
```

## Viewing Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f worker
docker-compose logs -f frontend
```

## Troubleshooting

### Can't access the frontend
- Check if port 5173 is available
- Try: `docker-compose restart frontend`

### Scans not starting
- Check worker logs: `docker-compose logs worker`
- Verify Redis is running: `docker-compose ps`

### No vulnerabilities found
- CVE lookup requires internet connection
- Some services may not have known CVEs
- Try scanning well-known vulnerable test targets

## Security Reminders

⚠️ **IMPORTANT**:
- Only scan networks you own or have permission to scan
- Unauthorized scanning may be illegal
- All actions are logged for audit purposes
- Use responsibly and ethically

## Getting Help

- Check the full documentation in `README.md`
- API documentation in `API.md`
- Development guide in `DEVELOPMENT.md`

## Sample Targets for Testing

**Legal test targets** (with permission):
- Your own local network: `192.168.1.0/24`
- Scanme.nmap.org: `scanme.nmap.org`
- Your own servers

**Never scan without permission!**

---

Happy scanning! 🐕🔍
