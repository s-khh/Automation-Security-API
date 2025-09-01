import jwt
import json
import time
import hashlib
import secrets
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
import requests
from .api_client import SecurityAPIClient

class AuthSecurityTester:

    def __init__(self, api_client: SecurityAPIClient):
        self.client = api_client
        self.tokens = {}
        self.session_data = {}

    def generate_interview_token(self) -> str:
        try:
            response = self.client.make_request(
                'POST',
                '/users/generate-token-for-interview-task',
                track_request=False
            )
            if response.status_code == 200:
                data = response.json()
                token = data.get('token', '')
                self.tokens['interview'] = token
                return token
            else:
                raise Exception(f"Token generation failed: {response.status_code}")
        except Exception as e:
            self.client.logger.error(f"Failed to generate interview token: {str(e)}")
            raise

    def analyze_jwt_token(self, token: str) -> Dict[str, Any]:
        analysis = {
            'is_jwt': False,
            'vulnerabilities': [],
            'claims': {},
            'header': {},
            'signature_valid': False
        }
        try:
            if token.count('.') == 2:
                analysis['is_jwt'] = True
                header = jwt.get_unverified_header(token)
                claims = jwt.decode(token, options={"verify_signature": False})
                analysis['header'] = header
                analysis['claims'] = claims
                vulnerabilities = []
                if header.get('alg') == 'none':
                    vulnerabilities.append({
                        'type': 'Weak Algorithm',
                        'severity': 'CRITICAL',
                        'description': 'JWT uses "none" algorithm - no signature verification'
                    })
                if 'exp' not in claims:
                    vulnerabilities.append({
                        'type': 'Missing Expiration',
                        'severity': 'HIGH',
                        'description': 'JWT token has no expiration time'
                    })
                else:
                    exp_time = datetime.fromtimestamp(claims['exp'])
                    if exp_time > datetime.now() + timedelta(days=30):
                        vulnerabilities.append({
                            'type': 'Long Expiration',
                            'severity': 'MEDIUM',
                            'description': f'JWT token expires too far in future: {exp_time}'
                        })
                sensitive_fields = ['password', 'secret', 'key', 'ssn', 'credit_card', 'social_security']
                for field in sensitive_fields:
                    if field in [k.lower() for k in claims.keys()] or \
                       any(field == str(value).lower() for value in claims.values() if isinstance(value, str)):
                        vulnerabilities.append({
                            'type': 'Sensitive Data in JWT',
                            'severity': 'HIGH',
                            'description': f'JWT contains sensitive data: {field}'
                        })
                business_sensitive_fields = {
                    'businessId': 'Internal business identifier exposed',
                    'businessName': 'Business name exposed in client token',
                    'sessionId': 'Session ID exposed (session hijacking risk)',
                    '_id': 'Internal database ID exposed'
                }
                def check_nested_dict(data, parent_key=''):
                    if isinstance(data, dict):
                        for key, value in data.items():
                            full_key = f"{parent_key}.{key}" if parent_key else key
                            if key in business_sensitive_fields:
                                vulnerabilities.append({
                                    'type': 'Business Data in JWT',
                                    'severity': 'MEDIUM',
                                    'description': f'JWT contains business-sensitive data: {full_key} - {business_sensitive_fields[key]}',
                                    'field': full_key,
                                    'value': str(value)[:50] + '...' if len(str(value)) > 50 else str(value)
                                })
                            check_nested_dict(value, full_key)
                    elif isinstance(data, list):
                        for i, item in enumerate(data):
                            check_nested_dict(item, f"{parent_key}[{i}]" if parent_key else f"[{i}]")
                check_nested_dict(claims)
                if 'roles' in claims and isinstance(claims['roles'], list):
                    if 'ADMIN' in claims['roles'] or 'SUPER_USER' in claims['roles']:
                        vulnerabilities.append({
                            'type': 'Privileged Role in JWT',
                            'severity': 'HIGH',
                            'description': 'JWT contains privileged roles that could be manipulated'
                        })
                analysis['vulnerabilities'] = vulnerabilities
        except Exception as e:
            self.client.logger.debug(f"JWT analysis failed: {str(e)}")
        return analysis

    def test_token_manipulation(self, original_token: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        if not original_token:
            return vulnerabilities
        if original_token.count('.') == 2:
            try:
                header, payload, signature = original_token.split('.')
                no_sig_token = f"{header}.{payload}."
                vuln = self._test_token_validity(no_sig_token, "No Signature")
                if vuln:
                    vulnerabilities.append(vuln)
                import base64
                header_data = json.loads(base64.urlsafe_b64decode(header + '=='))
                header_data['alg'] = 'none'
                modified_header = base64.urlsafe_b64encode(
                    json.dumps(header_data).encode()
                ).decode().rstrip('=')
                none_alg_token = f"{modified_header}.{payload}."
                vuln = self._test_token_validity(none_alg_token, "Algorithm None")
                if vuln:
                    vulnerabilities.append(vuln)
                payload_data = json.loads(base64.urlsafe_b64decode(payload + '=='))
                if 'roles' in payload_data:
                    original_roles = payload_data['roles'].copy()
                    privilege_escalation_tests = [
                        ('ADMIN', 'Added ADMIN role'),
                        ('SUPER_ADMIN', 'Added SUPER_ADMIN role'),
                        ('SUPER_USER', 'Added SUPER_USER role'),
                        ('ROOT', 'Added ROOT role'),
                        ('SYSTEM_ADMIN', 'Added SYSTEM_ADMIN role'),
                        ('DEVELOPER', 'Added DEVELOPER role'),
                        ('OWNER', 'Added OWNER role'),
                        (['ADMIN', 'SUPER_USER'], 'Added multiple privileged roles'),
                    ]
                    for test_role, description in privilege_escalation_tests:
                        test_payload_data = payload_data.copy()
                        if isinstance(test_role, list):
                            test_payload_data['roles'] = original_roles + test_role
                        else:
                            test_payload_data['roles'] = original_roles + [test_role]
                        modified_payload = base64.urlsafe_b64encode(
                            json.dumps(test_payload_data).encode()
                        ).decode().rstrip('=')
                        escalated_token = f"{header}.{modified_payload}.{signature}"
                        vuln = self._test_token_validity(escalated_token, f"Privilege Escalation - {description}")
                        if vuln:
                            vuln['original_roles'] = original_roles
                            vuln['escalated_roles'] = test_payload_data['roles']
                            vulnerabilities.append(vuln)
                if 'businessAdminInfo' in payload_data and 'businessId' in payload_data['businessAdminInfo']:
                    original_business_id = payload_data['businessAdminInfo']['businessId']
                    payload_data['businessAdminInfo']['businessId'] = 'MODIFIED_BUSINESS_ID'
                    modified_payload = base64.urlsafe_b64encode(
                        json.dumps(payload_data).encode()
                    ).decode().rstrip('=')
                    business_token = f"{header}.{modified_payload}.{signature}"
                    vuln = self._test_token_validity(business_token, "Business ID Manipulation")
                    if vuln:
                        vulnerabilities.append(vuln)
            except Exception as e:
                self.client.logger.debug(f"Token manipulation test failed: {str(e)}")
        vuln = self._test_token_validity("", "Empty Token")
        if vuln:
            vulnerabilities.append(vuln)
        invalid_tokens = [
            "invalid_token",
            "Bearer invalid",
            original_token + "modified",
            original_token[:-10],
        ]
        for invalid_token in invalid_tokens:
            vuln = self._test_token_validity(invalid_token, f"Invalid Token: {invalid_token[:20]}...")
            if vuln:
                vulnerabilities.append(vuln)
        return vulnerabilities

    def _test_token_validity(self, token: str, test_type: str, endpoint: str = '/businesses/add-bank-info') -> Optional[Dict[str, Any]]:
        try:
            test_data = {
                "bankInfo": {
                    "beneficiaryName": "test",
                    "bankName": "test bank",
                    "ibanNumber": "EG1234567890123456789",
                    "accountNumber": "123"
                },
                "paymentInfoOtp": "123456"
            }
            response = self.client.make_request(
                'POST',
                endpoint,
                data=test_data,
                auth_token=token,
                track_request=False,
                bypass_rate_limit=True
            )
            if response.status_code not in [401, 403] and not (response.status_code == 400 and 'OTP' in response.text):
                return {
                    'type': 'Token Manipulation Accepted',
                    'severity': 'CRITICAL',
                    'description': f'{test_type} token was accepted by the API',
                    'status_code': response.status_code,
                    'test_type': test_type,
                    'response_body': response.text[:200]
                }
        except Exception as e:
            self.client.logger.debug(f"Token validity test failed: {str(e)}")
        return None

    def test_session_management(self, token: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        different_headers = [
            {"user-agent": "Different-User-Agent/1.0"},
            {"x-forwarded-for": "192.168.1.100"},
            {"x-real-ip": "10.0.0.1"}
        ]
        for headers in different_headers:
            try:
                response = self.client.make_request(
                    'POST',
                    '/pickups',
                    data={"test": "session_test"},
                    auth_token=token,
                    headers=headers,
                    track_request=False
                )
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Session Fixation',
                        'severity': 'MEDIUM',
                        'description': 'Token accepted from different client context',
                        'headers': headers
                    })
            except Exception as e:
                self.client.logger.debug(f"Session management test failed: {str(e)}")
        return vulnerabilities

    def test_authorization_bypass(self, token: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        test_endpoints = [
            {'path': '/businesses/add-bank-info', 'method': 'POST'},
            {'path': '/users/forget-password', 'method': 'POST'},
            {'path': '/pickups', 'method': 'POST'},
        ]
        for endpoint in test_endpoints:
            try:
                response = self.client.make_request(
                    endpoint['method'],
                    endpoint['path'],
                    data={"test": "authorization_test"},
                    auth_token=token,
                    track_request=False
                )
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, dict) and len(data) > 0:
                            vulnerabilities.append({
                                'type': 'Authorization Bypass',
                                'severity': 'HIGH',
                                'description': f'Token provided access to {endpoint["path"]}',
                                'endpoint': endpoint['path'],
                                'response_keys': list(data.keys()) if isinstance(data, dict) else None
                            })
                    except:
                        pass
            except Exception as e:
                self.client.logger.debug(f"Authorization bypass test failed: {str(e)}")
        return vulnerabilities

    def test_brute_force_protection(self, endpoint: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        rapid_requests = 20
        successful_requests = 0
        start_time = time.time()
        for i in range(rapid_requests):
            try:
                response = self.client.make_request(
                    'POST',
                    endpoint,
                    data={"email": f"test{i}@example.com"},
                    bypass_rate_limit=False,
                    track_request=False
                )
                if response.status_code != 429:
                    successful_requests += 1
            except Exception as e:
                self.client.logger.debug(f"Brute force test request failed: {str(e)}")
        end_time = time.time()
        if successful_requests > rapid_requests * 0.8:
            vulnerabilities.append({
                'type': 'Insufficient Rate Limiting',
                'severity': 'MEDIUM',
                'description': f'{successful_requests}/{rapid_requests} requests succeeded in {end_time - start_time:.2f}s',
                'endpoint': endpoint,
                'successful_requests': successful_requests,
                'total_requests': rapid_requests,
                'time_taken': end_time - start_time
            })
        return vulnerabilities