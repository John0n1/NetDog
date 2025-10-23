# NetDog API Documentation

## Authentication

All API requests (except `/auth/token` and `/auth/register`) require a JWT bearer token.

### Register a new user

```bash
POST /api/v1/auth/register
Content-Type: application/json

{
  "username": "admin",
  "email": "admin@example.com",
  "password": "SecurePassword123",
  "full_name": "Admin User"
}
```

### Login

```bash
POST /api/v1/auth/token
Content-Type: application/x-www-form-urlencoded

username=admin&password=SecurePassword123
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer"
}
```

## Scans

### Start a new scan

```bash
POST /api/v1/scan
Authorization: Bearer <token>
Content-Type: application/json

{
  "targets": ["192.168.1.0/24", "10.0.0.1"],
  "mode": "normal",
  "consent": {
    "approved": true,
    "by": "admin",
    "reason": "Authorized security audit"
  }
}
```

Response:
```json
{
  "scan_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

### Get scan status

```bash
GET /api/v1/scan/{scan_id}
Authorization: Bearer <token>
```

### List scans

```bash
GET /api/v1/scans?limit=50&status_filter=running
Authorization: Bearer <token>
```

## Devices

### List devices

```bash
GET /api/v1/devices?scan_id={scan_id}&limit=100
Authorization: Bearer <token>
```

### Get device details

```bash
GET /api/v1/device/{device_id}
Authorization: Bearer <token>
```

## Vulnerabilities

### List vulnerabilities

```bash
GET /api/v1/vulns?severity=HIGH&limit=100
Authorization: Bearer <token>
```

### Get vulnerability details

```bash
GET /api/v1/vuln/{vuln_id}
Authorization: Bearer <token>
```

### Get vulnerability statistics

```bash
GET /api/v1/vulns/stats
Authorization: Bearer <token>
```

## Network Utilities

### Ping

```bash
POST /api/v1/netutil/ping
Authorization: Bearer <token>
Content-Type: application/json

{
  "target": "8.8.8.8",
  "count": 4,
  "consent": {
    "approved": true,
    "by": "admin",
    "reason": "Network diagnostics"
  }
}
```

### Speed Test

```bash
POST /api/v1/netutil/speedtest
Authorization: Bearer <token>
Content-Type: application/json

{
  "consent": {
    "approved": true,
    "by": "admin",
    "reason": "Connection testing"
  }
}
```

### DNS Lookup

```bash
POST /api/v1/netutil/dns-lookup?hostname=example.com
Authorization: Bearer <token>
```

## WebSocket Endpoints

### Connect to scan logs

```javascript
const ws = new WebSocket('ws://localhost:8000/api/v1/ws/logs?scan_id={scan_id}')

ws.onmessage = (event) => {
  const data = JSON.parse(event.data)
  if (data.type === 'console.log') {
    console.log(data.data)
  }
}
```

### Connect to scan progress

```javascript
const ws = new WebSocket('ws://localhost:8000/api/v1/ws/scan/{scan_id}')

ws.onmessage = (event) => {
  const data = JSON.parse(event.data)
  if (data.type === 'scan.progress') {
    console.log(`Progress: ${data.data.percent}%`)
  }
}
```

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message here"
}
```

Common status codes:
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (missing or invalid token)
- `404` - Not Found
- `500` - Internal Server Error
