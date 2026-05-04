# AuthFlaw AI - Quick Start Guide

**Version:** 1.0.0

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

## 5-Minute Setup

### Step 1: Install Dependencies (2 minutes)

```bash
# Create and activate virtual environment
python -m venv authflaw_env
authflaw_env\Scripts\activate  # Windows
# source authflaw_env/bin/activate  # Linux/Mac

# Install packages
pip install -r requirements.txt
```

### Step 2: Install Ollama (2 minutes)

```bash
# Download and install from: https://ollama.ai/download

# After installation, pull the model:
ollama pull llama3.2
```

### Step 3: Start Burp Suite (1 minute)

1. Open Burp Suite (Community Edition is fine)
2. Go to Proxy → Intercept → Turn OFF
3. Ensure proxy is on 127.0.0.1:8080

### Step 4: Run AuthFlaw AI

```bash
python authflaw.py
```

Paste your HTTP request, press Enter twice, and watch the magic happen!

## Example Test Request

```
POST /api/login HTTP/2
Host: example.com
Content-Type: application/json

{"email":"test@test.com","password":"password123"}
```

## What Happens Next?

1. AI analyzes your request
2. Generates attack variants
3. Sends them through Burp
4. Analyzes responses
5. Reports vulnerabilities

All requests appear in Burp HTTP History for manual verification!

## Common Issues

**"Ollama not found"**
```bash
ollama serve  # Start Ollama service
ollama pull llama3.2  # Download model
```

**"Connection refused"**
- Make sure Burp Suite is running
- Check proxy is on 127.0.0.1:8080

**"SSL Error"**
- Install Burp CA certificate
- Or test HTTP endpoints first

## Next Steps

- Check `reports/findings.json` for results
- Review requests in Burp HTTP History
- Use Burp Repeater to verify findings
- Customize `config.yaml` for your needs

Happy hunting!
