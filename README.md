# 🔒 API Security Scanner

A full-stack Node.js application for automated API security testing. Detect vulnerabilities in your APIs including SQL Injection, XSS, Command Injection, and Path Traversal attacks.

![API Security Scanner](https://img.shields.io/badge/Version-1.0.0-blue)
![Node.js](https://img.shields.io/badge/Node.js-18+-green)
![React](https://img.shields.io/badge/React-18-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

## ✨ Features

- **🎯 Multiple Input Methods**: Upload Postman collections or paste CURL commands
- **🔍 Comprehensive Testing**: SQL Injection, XSS, Command Injection, Path Traversal
- **📊 Interactive Dashboard**: Real-time results with detailed vulnerability analysis
- **🎨 Modern UI**: Beautiful cyberpunk-themed interface
- **📥 Export Results**: Download scan results as JSON
- **⚙️ Configurable**: Adjust payload counts, injection locations, and scan types

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ installed
- npm or yarn package manager

### Installation

1. **Clone or navigate to the project directory**
   ```bash
   cd API-Pentesting
   ```

2. **Install all dependencies**
   ```bash
   npm run install:all
   ```
   Or manually:
   ```bash
   npm install
   cd frontend && npm install && cd ..
   ```

3. **Start the application**
   ```bash
   npm start
   ```

This will launch both the frontend (http://localhost:3000) and backend (http://localhost:5000) simultaneously.

## 📁 Project Structure

```
API-Pentesting/
├── backend/
│   └── server.js           # Express server with API endpoints
├── frontend/
│   ├── public/
│   │   └── index.html
│   └── src/
│       ├── App.js          # Main React component
│       ├── App.css
│       ├── index.js
│       ├── index.css
│       └── components/
│           ├── Header.js/.css
│           ├── InputPanel.js/.css
│           └── ResultsDashboard.js/.css
├── scanner/
│   ├── index.js            # Main scanner engine
│   ├── payloads.js         # Attack payloads database
│   ├── sql.js              # SQL injection scanner
│   ├── xss.js              # XSS scanner
│   ├── commandInjection.js # Command injection scanner
│   └── pathTraversal.js    # Path traversal scanner
├── samples/
│   ├── sample-collection.json    # Sample Postman collection
│   └── demo-results.json         # Demo scan results
├── package.json
└── README.md
```

## 🔧 API Endpoints

### Backend API (Port 5000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/scan-types` | List available vulnerability types |
| POST | `/api/parse/postman` | Parse Postman collection |
| POST | `/api/parse/curl` | Parse CURL commands |
| POST | `/api/scan` | Run full security scan |
| POST | `/api/scan/quick` | Quick scan single endpoint |
| GET | `/api/scan/:id` | Get scan status/results |
| POST | `/api/test-connection` | Test endpoint connectivity |

## 📝 Usage

### Option 1: Upload Postman Collection

1. Open the app at http://localhost:3000
2. Select "Postman Collection" tab
3. Drag & drop or click to upload your `.json` collection file
4. (Optional) Add environment variables
5. Configure scan options
6. Click "Run Security Tests"

### Option 2: Paste CURL Commands

1. Select "CURL Commands" tab
2. Paste one or more CURL commands
3. Configure scan options
4. Click "Run Security Tests"

### Example CURL

```bash
curl -X POST https://api.example.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123"}'
```

### Environment Variables

Use `{{variableName}}` syntax in your Postman collection or CURL commands:

```bash
curl -X GET {{baseUrl}}/users \
  -H "Authorization: Bearer {{token}}"
```

Then add variables in the UI:
- `baseUrl` → `https://api.example.com`
- `token` → `your-auth-token`

## 🛡️ Vulnerability Types

### SQL Injection
Tests for database injection vulnerabilities:
- Basic injection (`' OR '1'='1`)
- Union-based injection
- Time-based blind injection
- Error-based injection

### Cross-Site Scripting (XSS)
Tests for script injection:
- Reflected XSS (`<script>alert(1)</script>`)
- Event handler injection
- SVG-based XSS
- Template injection

### Command Injection
Tests for OS command execution:
- Unix commands (`; ls`, `| whoami`)
- Windows commands (`& dir`, `| type`)
- Backtick execution
- Subshell execution

### Path Traversal
Tests for file system access:
- Directory traversal (`../../../etc/passwd`)
- Windows paths (`..\\..\\windows\\system.ini`)
- URL encoded variants
- Null byte injection

## 📊 Results Format

```json
{
  "scanId": "uuid",
  "timestamp": "2024-01-15T10:30:00Z",
  "duration": 15000,
  "summary": {
    "totalEndpoints": 5,
    "totalTests": 100,
    "passed": 95,
    "failed": 5,
    "vulnerabilities": [...]
  },
  "endpoints": [
    {
      "api": "/login",
      "method": "POST",
      "tests": [
        {
          "type": "SQL Injection",
          "payload": "' OR '1'='1",
          "result": "FAIL",
          "responseCode": 200,
          "confidence": "high",
          "notes": "Authentication bypass detected"
        }
      ]
    }
  ]
}
```

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Always:

- ✅ Get written permission before testing any API
- ✅ Test only on systems you own or have explicit authorization to test
- ✅ Use responsibly and ethically
- ❌ Never use on production systems without proper safeguards
- ❌ Never use for malicious purposes

## 🔧 Configuration

### Scan Options

| Option | Values | Description |
|--------|--------|-------------|
| Payloads per Type | 3, 5, 10, 20 | Number of payloads to test |
| Injection Location | all, query, body, header, path | Where to inject payloads |
| Scan Types | SQL, XSS, Command, Path | Which vulnerabilities to test |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 5000 | Backend server port |

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- OWASP for vulnerability documentation
- The security community for payload research

