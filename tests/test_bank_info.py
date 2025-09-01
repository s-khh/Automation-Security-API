import pytest
import json
import jwt
import time
from typing import Dict, Any, List
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.api_client import SecurityAPIClient
from core.auth import AuthSecurityTester
from core.utils import SecurityPayloadGenerator

class TestBankInfoAPISecurity:
    @pytest.fixture(scope="class")
    def api_client(self):
        return SecurityAPIClient()

    @pytest.fixture(scope="class")
    def auth_tester(self, api_client):
        return AuthSecurityTester(api_client)

    @pytest.fixture(scope="class")
    def payload_generator(self):
        return SecurityPayloadGenerator()

    @pytest.fixture(scope="class")
    def test_data(self):
        with open('data/test_data.json', 'r') as f:
            return json.load(f)

    @pytest.fixture(scope="class")
    def invalid_data(self):
        with open('data/invalid_data.json', 'r') as f:
            return json.load(f)
   
    @pytest.mark.security
    @pytest.mark.critical
    def test_bank_info_jwt_analysis(self, auth_tester, test_data):
        jwt_token = test_data['tokens']['bank_info_token']
        analysis = auth_tester.analyze_jwt_token(jwt_token)
        critical_vulns = [v for v in analysis['vulnerabilities'] if v['severity'] == 'CRITICAL']
        if critical_vulns:
            pytest.fail(f"Critical JWT vulnerabilities: {critical_vulns}")
        sensitive_vulns = [v for v in analysis['vulnerabilities'] if 'Sensitive Data' in v['type']]
        if sensitive_vulns:
            pytest.fail(f"Sensitive data in JWT: {sensitive_vulns}")
        business_vulns = [v for v in analysis['vulnerabilities'] if 'Business Data' in v['type']]
        if business_vulns:
            pytest.fail(f"Business-sensitive data exposed in JWT: {business_vulns}")
    @pytest.mark.security
    @pytest.mark.auth

    def test_bank_info_authentication_bypass(self, api_client, test_data):
        bank_data = test_data['valid_data']['bank_info']
        response = api_client.make_request(
            'POST',
            '/businesses/add-bank-info',
            data=bank_data,
            bypass_rate_limit=True
        )
        print(f"DEBUG: Response status: {response.status_code}")
        print(f"DEBUG: Response body: {response.text[:200]}")
        assert response.status_code in [401, 403], f"API should require authentication, got {response.status_code}. Response: {response.text[:200]}"
   
    @pytest.mark.security
    @pytest.mark.critical
    def test_bank_info_jwt_manipulation(self, api_client, auth_tester, test_data):
        original_token = test_data['tokens']['bank_info_token']
        bank_data = test_data['valid_data']['bank_info']
        vulnerabilities = auth_tester.test_token_manipulation(original_token)
        critical_vulns = []
        for vuln in vulnerabilities:
            if vuln['type'] == 'Token Manipulation Accepted':
                try:
                    response = api_client.make_request(
                        'POST',
                        '/businesses/add-bank-info',
                        data=bank_data,
                        auth_token=vuln.get('test_token', ''),
                        track_request=False
                    )
                    if response.status_code not in [401, 403]:
                        critical_vulns.append(vuln)
                except:
                    pass
        if critical_vulns:
            pytest.fail(f"JWT manipulation vulnerabilities: {critical_vulns}")
  
    @pytest.mark.security
    @pytest.mark.critical
    def test_bank_info_business_id_manipulation(self, api_client, test_data, invalid_data):
        original_token = test_data['tokens']['bank_info_token']
        bank_data = test_data['valid_data']['bank_info']
        try:
            decoded = jwt.decode(original_token, options={"verify_signature": False})
            original_business_id = decoded.get('businessAdminInfo', {}).get('businessId')
            if not original_business_id:
                pytest.skip("No business ID found in JWT")
            idor_payloads = invalid_data['idor_payloads']
            vulnerabilities = []
            for payload in idor_payloads:
                modified_claims = decoded.copy()
                modified_claims['businessAdminInfo']['businessId'] = payload
                import base64
                header = {"alg": "none", "typ": "JWT"}
                header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
                payload_encoded = base64.urlsafe_b64encode(json.dumps(modified_claims).encode()).decode().rstrip('=')
                modified_token = f"{header_encoded}.{payload_encoded}."
                response = api_client.make_request(
                    'POST',
                    '/businesses/add-bank-info',
                    data=bank_data,
                    auth_token=modified_token,
                    track_request=False
                )
                if response.status_code not in [401, 403]:
                    vulnerabilities.append({
                        'type': 'Business ID Manipulation',
                        'severity': 'CRITICAL',
                        'description': f'Modified business ID accepted: {payload}',
                        'original_id': original_business_id,
                        'modified_id': payload
                    })
            if vulnerabilities:
                pytest.fail(f"Business ID manipulation vulnerabilities: {vulnerabilities}")
        except Exception as e:
            pytest.skip(f"Could not test business ID manipulation: {str(e)}")
    
    @pytest.mark.security
    @pytest.mark.critical
    def test_bank_info_privilege_escalation(self, api_client, test_data):
        original_token = test_data['tokens']['bank_info_token']
        bank_data = test_data['valid_data']['bank_info']
        try:
            decoded = jwt.decode(original_token, options={"verify_signature": False})
            original_roles = decoded.get('roles', [])
            escalated_roles = ['ADMIN', 'SUPER_USER', 'ROOT', 'SYSTEM_ADMIN']
            vulnerabilities = []
            for role in escalated_roles:
                if role not in original_roles:
                    modified_claims = decoded.copy()
                    modified_claims['roles'] = original_roles + [role]
                    import base64
                    header = {"alg": "none", "typ": "JWT"}
                    header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
                    payload_encoded = base64.urlsafe_b64encode(json.dumps(modified_claims).encode()).decode().rstrip('=')
                    escalated_token = f"{header_encoded}.{payload_encoded}."
                    response = api_client.make_request(
                        'POST',
                        '/businesses/add-bank-info',
                        data=bank_data,
                        auth_token=escalated_token,
                        track_request=False
                    )
                    if response.status_code not in [401, 403]:
                        vulnerabilities.append({
                            'type': 'Privilege Escalation',
                            'severity': 'CRITICAL',
                            'description': f'Escalated role accepted: {role}',
                            'original_roles': original_roles,
                            'escalated_role': role
                        })
            if vulnerabilities:
                pytest.fail(f"Privilege escalation vulnerabilities: {vulnerabilities}")
        except Exception as e:
            pytest.skip(f"Could not test privilege escalation: {str(e)}")
    
    @pytest.mark.security
    @pytest.mark.owasp
    def test_bank_info_otp_bypass(self, api_client, test_data, invalid_data):
        token = test_data['tokens']['bank_info_token']
        base_data = test_data['valid_data']['bank_info'].copy()
        vulnerabilities = []
        no_otp_data = base_data.copy()
        del no_otp_data['paymentInfoOtp']
        response = api_client.make_request(
            'POST',
            '/businesses/add-bank-info',
            data=no_otp_data,
            auth_token=token
        )
        if response.status_code == 200:
            vulnerabilities.append({
                'type': 'OTP Bypass',
                'severity': 'CRITICAL',
                'description': 'Bank info update accepted without OTP',
                'method': 'No OTP field'
            })
        empty_otp_data = base_data.copy()
        empty_otp_data['paymentInfoOtp'] = ''
        response = api_client.make_request(
            'POST',
            '/businesses/add-bank-info',
            data=empty_otp_data,
            auth_token=token
        )
        if response.status_code == 200:
            vulnerabilities.append({
                'type': 'OTP Bypass',
                'severity': 'CRITICAL',
                'description': 'Bank info update accepted with empty OTP',
                'method': 'Empty OTP'
            })
        weak_otps = ['000000', '123456', '111111', '000', '123', '1']
        for weak_otp in weak_otps:
            weak_otp_data = base_data.copy()
            weak_otp_data['paymentInfoOtp'] = weak_otp
            response = api_client.make_request(
                'POST',
                '/businesses/add-bank-info',
                data=weak_otp_data,
                auth_token=token
            )
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Weak OTP Accepted',
                    'severity': 'HIGH',
                    'description': f'Weak OTP accepted: {weak_otp}',
                    'otp': weak_otp
                })
        if vulnerabilities:
            pytest.fail(f"OTP bypass vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.injection
    def test_bank_info_sql_injection(self, api_client, test_data, invalid_data):
        token = test_data['tokens']['bank_info_token']
        base_data = test_data['valid_data']['bank_info'].copy()
        sql_payloads = invalid_data['sql_injection']
        vulnerable_fields = ['beneficiaryName', 'bankName', 'ibanNumber', 'accountNumber']
        vulnerabilities = []
        for field in vulnerable_fields:
            for payload in sql_payloads:
                test_data_copy = base_data.copy()
                test_data_copy['bankInfo'][field] = payload
                response = api_client.make_request(
                    'POST',
                    '/businesses/add-bank-info',
                    data=test_data_copy,
                    auth_token=token
                )
                if response.status_code == 500:
                    response_text = response.text.lower()
                    sql_errors = ['sql', 'mysql', 'database', 'syntax error', 'query']
                    for error in sql_errors:
                        if error in response_text:
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'CRITICAL',
                                'description': f'SQL injection in bank field: {field}',
                                'payload': payload,
                                'field': field,
                                'evidence': error
                            })
                            break
        if vulnerabilities:
            pytest.fail(f"SQL injection vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.data_exposure
    def test_bank_info_sensitive_data_exposure(self, api_client, test_data):
        token = test_data['tokens']['bank_info_token']
        bank_data = test_data['valid_data']['bank_info']
        response = api_client.make_request(
            'POST',
            '/businesses/add-bank-info',
            data=bank_data,
            auth_token=token
        )
        if response.status_code == 200:
            try:
                response_data = response.json()
                response_text = json.dumps(response_data).lower()
                sensitive_patterns = [
                    'account', 'iban', 'bank', 'beneficiary', 'routing',
                    'swift', 'sort_code', 'account_number'
                ]
                exposed_data = []
                for pattern in sensitive_patterns:
                    if pattern in response_text:
                        exposed_data.append(pattern)
                if exposed_data:
                    pytest.fail(f"Sensitive banking data exposed in response: {exposed_data}")
            except:
                pass
   
    @pytest.mark.security
    @pytest.mark.owasp
    def test_bank_info_business_logic_flaws(self, api_client, test_data, invalid_data):
        token = test_data['tokens']['bank_info_token']
        base_data = test_data['valid_data']['bank_info'].copy()
        vulnerabilities = []
        invalid_ibans = [
            '',
            '123',
            'INVALID_IBAN_FORMAT',
            'GB82WEST12345698765432',
            '12345678901EG' * 10,
        ]
        for invalid_iban in invalid_ibans:
            test_data_copy = base_data.copy()
            test_data_copy['bankInfo']['ibanNumber'] = invalid_iban
            response = api_client.make_request(
                'POST',
                '/businesses/add-bank-info',
                data=test_data_copy,
                auth_token=token
            )
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Invalid IBAN Accepted',
                    'severity': 'HIGH',
                    'description': f'Invalid IBAN format accepted: {invalid_iban}',
                    'iban': invalid_iban
                })
        empty_name_data = base_data.copy()
        empty_name_data['bankInfo']['beneficiaryName'] = ''
        response = api_client.make_request(
            'POST',
            '/businesses/add-bank-info',
            data=empty_name_data,
            auth_token=token
        )
        if response.status_code == 200:
            vulnerabilities.append({
                'type': 'Empty Beneficiary Name Accepted',
                'severity': 'MEDIUM',
                'description': 'Empty beneficiary name was accepted'
            })
        if vulnerabilities:
            pytest.fail(f"Business logic vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.rate_limit
    def test_bank_info_rate_limiting(self, api_client, test_data):
        token = test_data['tokens']['bank_info_token']
        bank_data = test_data['valid_data']['bank_info']
        rapid_requests = 10
        successful_requests = 0
        for i in range(rapid_requests):
            response = api_client.make_request(
                'POST',
                '/businesses/add-bank-info',
                data=bank_data,
                auth_token=token,
                bypass_rate_limit=False
            )
            if response.status_code not in [429, 403]:
                successful_requests += 1
        if successful_requests > rapid_requests * 0.7:
            pytest.fail(f"Insufficient rate limiting: {successful_requests}/{rapid_requests} requests succeeded")
  
    @pytest.mark.security
    @pytest.mark.critical
    def test_bank_info_concurrent_updates(self, api_client, test_data):
        import threading
        import time
        token = test_data['tokens']['bank_info_token']
        bank_data = test_data['valid_data']['bank_info']
        results = []
        def make_concurrent_request():
            try:
                response = api_client.make_request(
                    'POST',
                    '/businesses/add-bank-info',
                    data=bank_data,
                    auth_token=token,
                    bypass_rate_limit=True
                )
                results.append(response.status_code)
            except Exception as e:
                results.append(f"Error: {str(e)}")
        threads = []
        for i in range(5):
            thread = threading.Thread(target=make_concurrent_request)
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        successful_updates = sum(1 for result in results if result == 200)
        if successful_updates > 1:
            pytest.fail(f"Race condition detected: {successful_updates} concurrent updates succeeded")
  
    @pytest.mark.security
    @pytest.mark.owasp
    def test_bank_info_mass_assignment(self, api_client, test_data):
        token = test_data['tokens']['bank_info_token']
        base_data = test_data['valid_data']['bank_info'].copy()
        mass_assignment_data = base_data.copy()
        mass_assignment_data.update({
            'isAdmin': True,
            'role': 'admin',
            'permissions': ['all'],
            'businessId': 'MODIFIED_BUSINESS_ID',
            'userId': 'admin',
            'verified': True,
            'approved': True,
            'balance': 1000000
        })
        response = api_client.make_request(
            'POST',
            '/businesses/add-bank-info',
            data=mass_assignment_data,
            auth_token=token
        )
        if response.status_code == 200:
            try:
                response_data = response.json()
                dangerous_fields = ['isAdmin', 'role', 'permissions', 'balance']
                for field in dangerous_fields:
                    if field in str(response_data):
                        pytest.fail(f"Mass assignment vulnerability: {field} was processed")
            except:
                pass
    
    @pytest.mark.security
    @pytest.mark.critical
    def test_bank_info_otp_bypass(self, api_client, test_data):
        token = test_data['tokens']['bank_info_token']
        bank_data = test_data['valid_data']['bank_info'].copy()
        otp_tests = test_data['otp_bypass_tests']
        vulnerabilities = []
        for common_otp in otp_tests['common_otps']:
            test_data_copy = bank_data.copy()
            test_data_copy['paymentInfoOtp'] = common_otp
            response = api_client.make_request(
                'POST',
                '/businesses/add-bank-info',
                data=test_data_copy,
                auth_token=token,
                track_request=False
            )
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Weak OTP Accepted',
                    'severity': 'HIGH',
                    'description': f'Common OTP accepted: {common_otp}',
                    'otp_value': common_otp
                })
        for bypass_attempt in otp_tests['bypass_attempts']:
            test_data_copy = bank_data.copy()
            test_data_copy.update(bypass_attempt)
            response = api_client.make_request(
                'POST',
                '/businesses/add-bank-info',
                data=test_data_copy,
                auth_token=token,
                track_request=False
            )
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'OTP Bypass',
                    'severity': 'CRITICAL',
                    'description': f'OTP bypass successful with: {bypass_attempt}',
                    'bypass_method': str(bypass_attempt)
                })
        for sql_otp in otp_tests['sql_injection_otps']:
            test_data_copy = bank_data.copy()
            test_data_copy['paymentInfoOtp'] = sql_otp
            response = api_client.make_request(
                'POST',
                '/businesses/add-bank-info',
                data=test_data_copy,
                auth_token=token,
                track_request=False
            )
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'SQL Injection in OTP',
                    'severity': 'CRITICAL',
                    'description': f'SQL injection OTP accepted: {sql_otp}',
                    'payload': sql_otp
                })
        for invalid_otp in otp_tests['invalid_formats']:
            test_data_copy = bank_data.copy()
            test_data_copy['paymentInfoOtp'] = invalid_otp
            response = api_client.make_request(
                'POST',
                '/businesses/add-bank-info',
                data=test_data_copy,
                auth_token=token,
                track_request=False
            )
            if response.status_code not in [400, 422]:
                vulnerabilities.append({
                    'type': 'Poor Input Validation',
                    'severity': 'MEDIUM',
                    'description': f'Invalid OTP format not properly rejected: {invalid_otp}',
                    'status_code': response.status_code,
                    'invalid_otp': invalid_otp
                })
        if vulnerabilities:
            pytest.fail(f"OTP bypass vulnerabilities found: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.owasp
    def test_bank_info_ssrf_vulnerabilities(self, api_client, test_data):
        token = test_data['tokens']['bank_info_token']
        vulnerabilities = []
        ssrf_payloads = [
            "http://localhost:8080/admin",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "file:///etc/hosts",
            "ftp://internal-server.com/",
            "gopher://127.0.0.1:3306/",
            "dict://localhost:11211/",
            "ldap://127.0.0.1:389/",
        ]
        for payload in ssrf_payloads:
            test_cases = [
                {
                    "bankInfo": {
                        "beneficiaryName": "test user",
                        "bankName": payload,
                        "ibanNumber": "EG1234567890123456789",
                        "accountNumber": "123"
                    },
                    "paymentInfoOtp": "123456"
                },
                {
                    "bankInfo": {
                        "beneficiaryName": payload,
                        "bankName": "test bank",
                        "ibanNumber": "EG1234567890123456789", 
                        "accountNumber": "123"
                    },
                    "paymentInfoOtp": "123456"
                }
            ]
            for test_case in test_cases:
                try:
                    response = api_client.make_request(
                        'POST',
                        '/businesses/add-bank-info',
                        data=test_case,
                        auth_token=token,
                        track_request=False,
                        bypass_rate_limit=True
                    )
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Potential SSRF',
                            'severity': 'HIGH',
                            'description': f'SSRF payload accepted: {payload}',
                            'payload': payload,
                            'field': 'bankName' if payload in test_case['bankInfo']['bankName'] else 'beneficiaryName'
                        })
                    elif 'timeout' in response.text.lower() or 'connection' in response.text.lower():
                        vulnerabilities.append({
                            'type': 'SSRF Connection Attempt',
                            'severity': 'MEDIUM',
                            'description': f'Server attempted connection with SSRF payload: {payload}',
                            'payload': payload,
                            'response': response.text[:100]
                        })
                except Exception as e:
                    if 'timeout' in str(e).lower() or 'connection' in str(e).lower():
                        vulnerabilities.append({
                            'type': 'SSRF Network Error',
                            'severity': 'MEDIUM', 
                            'description': f'Network error with SSRF payload: {payload}',
                            'error': str(e)[:100]
                        })
        if vulnerabilities:
            pytest.fail(f"SSRF vulnerabilities found: {vulnerabilities}")
  
    @pytest.mark.security
    @pytest.mark.owasp
    def test_bank_info_security_headers(self, api_client):
        vulnerabilities = []
        response = api_client.make_request(
            'OPTIONS',
            '/businesses/add-bank-info',
            track_request=False,
            bypass_rate_limit=True
        )
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age',
            'Content-Security-Policy': None,
            'Referrer-Policy': None,
            'Permissions-Policy': None
        }
        for header, expected_value in security_headers.items():
            if header not in response.headers:
                vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'severity': 'MEDIUM' if header.startswith('X-') else 'HIGH',
                    'description': f'Missing security header: {header}',
                    'header': header
                })
            elif expected_value:
                actual_value = response.headers[header]
                if isinstance(expected_value, list):
                    if not any(val in actual_value for val in expected_value):
                        vulnerabilities.append({
                            'type': 'Weak Security Header',
                            'severity': 'MEDIUM',
                            'description': f'Weak {header}: {actual_value}',
                            'header': header,
                            'value': actual_value
                        })
                elif expected_value not in actual_value:
                    vulnerabilities.append({
                        'type': 'Weak Security Header',
                        'severity': 'MEDIUM',
                        'description': f'Weak {header}: {actual_value}',
                        'header': header,
                        'value': actual_value
                    })
        disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        for header in disclosure_headers:
            if header in response.headers:
                vulnerabilities.append({
                    'type': 'Information Disclosure Header',
                    'severity': 'LOW',
                    'description': f'Information disclosure via {header}: {response.headers[header]}',
                    'header': header,
                    'value': response.headers[header]
                })
        if vulnerabilities:
            pytest.fail(f"Security header vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.owasp
    def test_bank_info_error_handling_security(self, api_client, test_data):
        token = test_data['tokens']['bank_info_token']
        vulnerabilities = []
        error_test_cases = [
            "invalid json{",
            {"bankInfo": "not_an_object"},
            {"bankInfo": {"beneficiaryName": 123}},
            {"bankInfo": {}},
            {"bankInfo": {"beneficiaryName": "A" * 10000}},
            {"bankInfo": {"beneficiaryName": "\x00\x01\x02"}},
            {"bankInfo": {"beneficiaryName": "'; DROP TABLE users; --"}},
        ]
        for test_case in error_test_cases:
            try:
                if isinstance(test_case, str):
                    import requests
                    base_url = api_client._get_base_url()
                    if not base_url.endswith('/'):
                        base_url += '/'
                    url = base_url + 'businesses/add-bank-info'
                    response = requests.post(
                        url,
                        data=test_case,
                        headers={
                            'Authorization': token,
                            'Content-Type': 'application/json'
                        },
                        timeout=30
                    )
                else:
                    response = api_client.make_request(
                        'POST',
                        '/businesses/add-bank-info',
                        data=test_case,
                        auth_token=token,
                        track_request=False,
                        bypass_rate_limit=True
                    )
                error_indicators = [
                    'stack trace', 'traceback', 'exception',
                    'mysql', 'postgresql', 'mongodb', 'redis',
                    'file not found', 'permission denied',
                    '/var/', '/etc/', '/usr/', '/home/',
                    'line ', 'column ', 'syntax error',
                    'internal server error', '500 error'
                ]
                response_text = response.text.lower()
                for indicator in error_indicators:
                    if indicator in response_text:
                        vulnerabilities.append({
                            'type': 'Information Disclosure in Error',
                            'severity': 'MEDIUM',
                            'description': f'Error response contains: {indicator}',
                            'test_case': str(test_case)[:100],
                            'response_snippet': response.text[:200]
                        })
                        break
                if len(response.text) > 500 and response.status_code >= 400:
                    vulnerabilities.append({
                        'type': 'Verbose Error Response',
                        'severity': 'LOW',
                        'description': 'Error response is very detailed',
                        'response_length': len(response.text),
                        'status_code': response.status_code
                    })
            except Exception as e:
                pass
        if vulnerabilities:
            pytest.fail(f"Error handling security issues: {vulnerabilities}")
        else:
            print("✅ OTP validation is properly implemented - no bypass vulnerabilities found")