# AuthFlaw AI

**AI-Powered Authentication Bypass Testing Tool**

```
   _____     ____ ___  ___________   ___ ___           ___________ .____         _____    __      __  
  /  _  \   |    |   \ \__    ___/  /   |   \          \_   _____/ |    |       /  |  |  /  \    /  \ 
 /  /_\  \  |    |   /   |    |    /    ~    \          |    __)   |    |      /   |  |_ \   \/\/   / 
/    |    \ |    |  /    |    |    \    Y    /          |     \    |    |___  /    ^   /  \        /  
\____|__  / |______/     |____|     \___|_  /   ______  \___  /    |_______ \ \____   |    \__/\  /   
        \/                                \/   /_____/      \/             \/      |__|         \/    
                                                                                                      
                                                                      _____    .___                   
  ______   ____   _____      ____     ____     ____   _______        /  _  \   |   |                  
 /  ___/ _/ ___\  \__  \    /    \   /    \  _/ __ \  \_  __ \      /  /_\  \  |   |                  
 \___ \  \  \___   / __ \_ |   |  \ |   |  \ \  ___/   |  | \/     /    |    \ |   |                  
/____  >  \___  > (____  / |___|  / |___|  /  \___  >  |__|        \____|__  / |___|                  
     \/       \/       \/       \/       \/       \/                       \/                         
```

**Version:** 1.0.0

AuthFlaw AI uses local AI (Ollama) and Model Context Protocol (MCP) to automatically detect and exploit authentication vulnerabilities in web applications. All requests are proxied through Burp Suite for manual verification.

## Features

- **AI-Powered Analysis** - Uses Ollama (local, free) to analyze requests
- **Burp Integration** - All requests appear in Burp HTTP History
- **Smart Attack Selection** - AI chooses relevant attack modules
- **Automated Testing** - Tests multiple variants automatically
- **Response Analysis** - AI evaluates responses for vulnerabilities
- **Free & Private** - No API costs, all processing local

## Supported Attacks

- SQL Injection Authentication Bypass
- Mass Assignment / Parameter Pollution
- JWT Algorithm Confusion (none, HS256/RS256)
- Host Header Injection
- Registration Privilege Escalation
- Session Fixation
- Rate Limit Bypass

## Installation

### 1. Install Python Dependencies

```bash
# Create virtual environment
python -m venv authflaw_env

# Activate (Windows)
authflaw_env\Scripts\activate

# Activate (Linux/Mac)
source authflaw_env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Install Ollama (Local AI)

```bash
# Download from https://ollama.ai
# Or use package manager:

# Windows (via installer)
# Download from https://ollama.ai/download

# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Mac
brew install ollama

# Pull the model
ollama pull llama3.2
```

### 3. Setup Burp Suite

1. Open Burp Suite (Community Edition works!)
2. Go to Proxy → Options
3. Ensure proxy listener is on `127.0.0.1:8080`
4. Go to Proxy → Intercept → Turn intercept OFF
5. (Optional) Install Burp CA certificate for HTTPS

## Usage

### Basic Usage

```bash
python authflaw.py
```

Then paste your HTTP request and press Enter twice.

### Example Request

```
POST /api/login HTTP/2
Host: example.com
Content-Type: application/json

{"email":"test@test.com","password":"password123"}
```

### Example Output

```
============================================================
AUTHFLAW AI - Authentication Bypass Tool
============================================================

[1/5] Parsing request...
  → Method: POST
  → Path: /api/login
  → Auth Type: JSON_Login

[2/5] AI analyzing request...
  → Auth mechanism: JSON_Login
  → Potential vulns: SQLi, MassAssignment
  → Modules to run: SQLi, MassAssignment, RegistrationPrivEsc

[3/5] Generating attack variants...
  → Generated 6 attack variants

[4/5] Testing via Burp proxy...

  [1/6] Testing: SQLi
    Payload: "email":"admin' OR '1'='1' --"...
    Response: HTTP 200
    [!] VULNERABLE! SQL injection detected

[5/5] Generating report...

========================================================================================================================
FINDINGS REPORT
========================================================================================================================

[!] Found 1 potential vulnerabilities:

  1. SQLi
     CVSS: 8.5
     Status: HTTP 200
     Payload: "email":"admin' OR '1'='1' --"...
     Vulnerability: SQL injection in email parameter

[*] All requests sent through Burp proxy - Check HTTP History
Report saved to reports/findings.json
```

## Project Structure

```
authflaw/
├── authflaw.py              # Main script
├── requirements.txt         # Python dependencies
├── config.yaml             # Configuration
├── README.md               # This file
├── modules/                # Attack modules
│   ├── __init__.py
│   ├── jwt_attacks.py
│   ├── sqli_bypass.py
│   ├── mass_assignment.py
│   ├── host_header.py
│   └── registration_priv_esc.py
└── reports/                # Generated reports
    └── findings.json
```

## Configuration

Edit `config.yaml` to customize:

- Burp proxy settings
- AI model selection
- Enabled attack modules
- Request timeouts
- Report formats

## Troubleshooting

### Ollama Not Found

```bash
# Check if Ollama is running
ollama list

# Start Ollama service (if needed)
ollama serve

# Pull model if missing
ollama pull llama3.2
```

### Burp Connection Failed

- Ensure Burp Suite is running
- Check proxy is on `127.0.0.1:8080`
- Disable intercept mode
- For HTTPS, install Burp CA certificate

### No Vulnerabilities Found

- Review requests in Burp HTTP History
- Manually test in Burp Repeater
- Try different attack modules
- Check if target has WAF/rate limiting

## Advanced Usage

### Custom Attack Modules

Create new modules in `modules/` directory:

```python
class CustomAttack:
    @staticmethod
    def get_payloads():
        return ["payload1", "payload2"]
```

### Batch Testing

Create a file with multiple requests and process them:

```python
with open('requests.txt', 'r') as f:
    requests = f.read().split('\n\n')
    for req in requests:
        tool.run(req)
```

## Legal Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before testing any system you don't own. Unauthorized access is illegal.

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please submit pull requests or open issues.

## Credits

- Built with Ollama (https://ollama.ai)
- Integrates with Burp Suite (https://portswigger.net)
- Uses Model Context Protocol (MCP)
