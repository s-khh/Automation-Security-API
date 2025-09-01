import pytest
import json
import time
import threading
from typing import Dict, Any, List
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.api_client import SecurityAPIClient
from core.auth import AuthSecurityTester
from core.utils import SecurityPayloadGenerator

class TestForgetPasswordAPISecurity:
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
    def test_forget_password_email_enumeration(self, api_client, test_data, invalid_data):
        valid_email = test_data['valid_data']['forget_password']['email']
        invalid_emails = invalid_data['invalid_emails']
        vulnerabilities = []
        valid_response = api_client.make_request(
            'POST',
            '/users/forget-password',
            data={'email': valid_email}
        )
        for invalid_email in invalid_emails:
            if invalid_email:
                invalid_response = api_client.make_request(
                    'POST',
                    '/users/forget-password',
                    data={'email': invalid_email}
                )
                if valid_response.status_code != invalid_response.status_code:
                    vulnerabilities.append({
                        'type': 'Email Enumeration',
                        'severity': 'HIGH',
                        'description': f'Different response codes: valid={valid_response.status_code}, invalid={invalid_response.status_code}',
                        'valid_email': valid_email,
                        'invalid_email': invalid_email
                    })
                if len(valid_response.text) != len(invalid_response.text):
                    vulnerabilities.append({
                        'type': 'Email Enumeration via Response Length',
                        'severity': 'MEDIUM',
                        'description': f'Response length differs: valid={len(valid_response.text)}, invalid={len(invalid_response.text)}',
                        'valid_email': valid_email,
                        'invalid_email': invalid_email
                    })
                start_time = time.time()
                api_client.make_request(
                    'POST',
                    '/users/forget-password',
                    data={'email': valid_email},
                    track_request=False
                )
                valid_time = time.time() - start_time
                start_time = time.time()
                api_client.make_request(
                    'POST',
                    '/users/forget-password',
                    data={'email': invalid_email},
                    track_request=False
                )
                invalid_time = time.time() - start_time
                if abs(valid_time - invalid_time) > 0.1:
                    vulnerabilities.append({
                        'type': 'Email Enumeration via Timing Attack',
                        'severity': 'MEDIUM',
                        'description': f'Timing difference: valid={valid_time:.3f}s, invalid={invalid_time:.3f}s',
                        'valid_email': valid_email,
                        'invalid_email': invalid_email
                    })
        if vulnerabilities:
            pytest.fail(f"Email enumeration vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.critical
    def test_forget_password_rate_limiting(self, api_client, test_data):
        email = test_data['valid_data']['forget_password']['email']
        rapid_requests = 20
        successful_requests = 0
        rate_limited_requests = 0
        start_time = time.time()
        for i in range(rapid_requests):
            response = api_client.make_request(
                'POST',
                '/users/forget-password',
                data={'email': email},
                bypass_rate_limit=False,
                track_request=False
            )
            if response.status_code == 200:
                successful_requests += 1
            elif response.status_code == 429:
                rate_limited_requests += 1
        end_time = time.time()
        if successful_requests > rapid_requests * 0.8:
            pytest.fail(f"Insufficient rate limiting: {successful_requests}/{rapid_requests} requests succeeded in {end_time - start_time:.2f}s")
        if rate_limited_requests == 0 and successful_requests > 5:
            pytest.fail("No rate limiting detected on forget password endpoint")
   
    @pytest.mark.security
    @pytest.mark.injection
    def test_forget_password_sql_injection(self, api_client, invalid_data):
        sql_payloads = invalid_data['sql_injection']
        vulnerabilities = []
        for payload in sql_payloads:
            response = api_client.make_request(
                'POST',
                '/users/forget-password',
                data={'email': payload}
            )
            if response.status_code == 500:
                response_text = response.text.lower()
                sql_errors = ['sql', 'mysql', 'database', 'syntax error', 'query', 'postgresql']
                for error in sql_errors:
                    if error in response_text:
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'description': f'SQL injection in email field',
                            'payload': payload,
                            'evidence': error
                        })
                        break
        if vulnerabilities:
            pytest.fail(f"SQL injection vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.injection
    def test_forget_password_nosql_injection(self, api_client, invalid_data):
        nosql_payloads = [
            {"$ne": ""},
            {"$regex": ".*"},
            {"$where": "this.email"},
            {"$gt": ""},
            {"email": {"$ne": ""}},
            "'; return true; var x='",
            "' || '1'=='1",
        ]
        vulnerabilities = []
        for payload in nosql_payloads:
            if isinstance(payload, str):
                test_data = {'email': payload}
            else:
                test_data = payload
            response = api_client.make_request(
                'POST',
                '/users/forget-password',
                data=test_data
            )
            if response.status_code == 500:
                response_text = response.text.lower()
                nosql_errors = ['mongodb', 'nosql', 'bson', 'mongoose', 'collection']
                for error in nosql_errors:
                    if error in response_text:
                        vulnerabilities.append({
                            'type': 'NoSQL Injection',
                            'severity': 'CRITICAL',
                            'description': f'NoSQL injection in email field',
                            'payload': str(payload),
                            'evidence': error
                        })
                        break
            elif response.status_code == 200 and not isinstance(payload, str):
                vulnerabilities.append({
                    'type': 'NoSQL Injection - Object Payload Accepted',
                    'severity': 'HIGH',
                    'description': 'Non-string payload accepted in email field',
                    'payload': str(payload)
                })
        if vulnerabilities:
            pytest.fail(f"NoSQL injection vulnerabilities: {vulnerabilities}")
    
    @pytest.mark.security
    @pytest.mark.xss
    def test_forget_password_xss_injection(self, api_client, invalid_data):
        xss_payloads = invalid_data['xss_payloads']
        vulnerabilities = []
        for payload in xss_payloads:
            response = api_client.make_request(
                'POST',
                '/users/forget-password',
                data={'email': payload}
            )
            if payload in response.text:
                vulnerabilities.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'HIGH',
                    'description': 'XSS payload reflected in response',
                    'payload': payload
                })
        if vulnerabilities:
            pytest.fail(f"XSS vulnerabilities: {vulnerabilities}")
    
    @pytest.mark.security
    @pytest.mark.owasp
    def test_forget_password_ldap_injection(self, api_client, invalid_data):
        ldap_payloads = [
            "*",
            "*)(&",
            "*)(uid=*",
            "*)(|(uid=*",
            "admin)(&(password=*",
            "admin))(|(uid=*",
        ]
        vulnerabilities = []
        for payload in ldap_payloads:
            response = api_client.make_request(
                'POST',
                '/users/forget-password',
                data={'email': payload}
            )
            if response.status_code == 500:
                response_text = response.text.lower()
                ldap_errors = ['ldap', 'directory', 'distinguished name', 'dn', 'objectclass']
                for error in ldap_errors:
                    if error in response_text:
                        vulnerabilities.append({
                            'type': 'LDAP Injection',
                            'severity': 'HIGH',
                            'description': 'LDAP injection in email field',
                            'payload': payload,
                            'evidence': error
                        })
                        break
        if vulnerabilities:
            pytest.fail(f"LDAP injection vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.owasp
    def test_forget_password_email_validation_bypass(self, api_client, invalid_data):
        invalid_emails = invalid_data['invalid_emails']
        malformed_emails = [
            "user@domain@domain.com",
            "user@@domain.com",
            "user@.domain.com",
            "user@domain..com",
            "user@domain.com.",
            ".user@domain.com",
            "user.@domain.com",
            "user@",
            "@domain.com",
            "user@domain",
            "user@domain.",
            "user name@domain.com",
            "user@domain .com",
        ]
        vulnerabilities = []
        for invalid_email in invalid_emails + malformed_emails:
            if invalid_email:
                response = api_client.make_request(
                    'POST',
                    '/users/forget-password',
                    data={'email': invalid_email}
                )
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Email Validation Bypass',
                        'severity': 'MEDIUM',
                        'description': f'Invalid email format accepted: {invalid_email}',
                        'invalid_email': invalid_email
                    })
        if vulnerabilities:
            pytest.fail(f"Email validation bypass vulnerabilities: {vulnerabilities}")
    
    @pytest.mark.security
    @pytest.mark.critical
    def test_forget_password_account_takeover(self, api_client, test_data):
        valid_email = test_data['valid_data']['forget_password']['email']
        case_variations = [
            valid_email.upper(),
            valid_email.lower(),
            valid_email.capitalize(),
            valid_email.swapcase(),
        ]
        vulnerabilities = []
        for variation in case_variations:
            if variation != valid_email:
                response = api_client.make_request(
                    'POST',
                    '/users/forget-password',
                    data={'email': variation}
                )
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Case Sensitivity Bypass',
                        'severity': 'HIGH',
                        'description': f'Email case variation accepted: {variation}',
                        'original_email': valid_email,
                        'variation': variation
                    })
        unicode_variations = [
            valid_email.replace('a', 'а'),
            valid_email.replace('o', 'о'),
            valid_email.replace('e', 'е'),
        ]
        for variation in unicode_variations:
            if variation != valid_email:
                response = api_client.make_request(
                    'POST',
                    '/users/forget-password',
                    data={'email': variation}
                )
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Unicode Homograph Attack',
                        'severity': 'HIGH',
                        'description': f'Unicode email variation accepted: {variation}',
                        'original_email': valid_email,
                        'variation': variation
                    })
        if vulnerabilities:
            pytest.fail(f"Account takeover vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.owasp
    def test_forget_password_mass_password_reset(self, api_client, test_data):
        base_email = test_data['valid_data']['forget_password']['email']
        domain = base_email.split('@')[1]
        test_emails = [
            f"user{i}@{domain}" for i in range(1, 11)
        ]
        successful_resets = 0
        for email in test_emails:
            response = api_client.make_request(
                'POST',
                '/users/forget-password',
                data={'email': email},
                bypass_rate_limit=True,
                track_request=False
            )
            if response.status_code == 200:
                successful_resets += 1
        if successful_resets > len(test_emails) * 0.5:
            pytest.fail(f"Mass password reset vulnerability: {successful_resets}/{len(test_emails)} resets succeeded")
   
    @pytest.mark.security
    @pytest.mark.owasp
    def test_forget_password_token_management(self, api_client, test_data):
        email = test_data['valid_data']['forget_password']['email']
        vulnerabilities = []
        for i in range(3):
            try:
                response = api_client.make_request(
                    'POST',
                    '/users/forget-password',
                    data={'email': email},
                    bypass_rate_limit=True,
                    track_request=False
                )
                if response.status_code not in [200, 201, 202]:
                    vulnerabilities.append({
                        'type': 'Password Reset Blocked',
                        'severity': 'LOW',
                        'description': f'Legitimate password reset request #{i+1} was blocked',
                        'status_code': response.status_code
                    })
            except Exception as e:
                vulnerabilities.append({
                    'type': 'Password Reset Error',
                    'severity': 'MEDIUM',
                    'description': f'Password reset request #{i+1} caused error: {str(e)}',
                    'error': str(e)
                })
        if vulnerabilities:
            pytest.fail(f"Password reset token management issues: {vulnerabilities}")
    
    @pytest.mark.security
    @pytest.mark.data_exposure
    def test_forget_password_information_disclosure(self, api_client, test_data):
        email = test_data['valid_data']['forget_password']['email']
        response = api_client.make_request(
            'POST',
            '/users/forget-password',
            data={'email': email}
        )
        vulnerabilities = api_client.analyze_response_for_vulnerabilities(response)
        if response.status_code == 200:
            try:
                response_data = response.json()
                response_text = json.dumps(response_data).lower()
                sensitive_patterns = [
                    'user_id', 'userid', 'id', 'username', 'phone', 'address',
                    'reset_token', 'token', 'secret', 'key', 'password'
                ]
                disclosed_info = []
                for pattern in sensitive_patterns:
                    if pattern in response_text:
                        disclosed_info.append(pattern)
                if disclosed_info:
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'MEDIUM',
                        'description': f'Sensitive information disclosed: {disclosed_info}',
                        'disclosed_fields': disclosed_info
                    })
            except:
                pass
        if vulnerabilities:
            pytest.fail(f"Information disclosure vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.slow
    def test_forget_password_comprehensive_fuzzing(self, api_client, payload_generator):
        vulnerabilities = []
        fuzz_payloads = [
            payload_generator.generate_random_string(1000),
            payload_generator.generate_random_string(10000),
            *payload_generator.generate_boundary_values('string'),
            ''.join(['A'] * 100000),
            '\x00\x01\x02\x03',
            '<?xml version="1.0"?><root>test</root>',
            '{"test": "json"}',
            '%00%01%02%03',
        ]
        for payload in fuzz_payloads:
            try:
                response = api_client.make_request(
                    'POST',
                    '/users/forget-password',
                    data={'email': payload},
                    track_request=False
                )
                if response.status_code == 500:
                    vulnerabilities.append({
                        'type': 'Server Error on Fuzzing',
                        'severity': 'MEDIUM',
                        'description': f'Server error with fuzzing payload',
                        'payload_type': type(payload).__name__,
                        'payload_length': len(str(payload))
                    })
            except Exception as e:
                vulnerabilities.append({
                    'type': 'Exception on Fuzzing',
                    'severity': 'LOW',
                    'description': f'Exception with fuzzing payload: {str(e)}',
                    'payload_type': type(payload).__name__
                })
        if vulnerabilities:
            print(f"Fuzzing found potential issues: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.owasp
    def test_forget_password_header_injection(self, api_client, test_data):
        email = test_data['valid_data']['forget_password']['email']
        malicious_headers = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '192.168.1.1',
            'X-Originating-IP': '10.0.0.1',
            'Host': 'evil.com',
            'Referer': 'http://evil.com',
            'Origin': 'http://evil.com',
        }
        vulnerabilities = []
        for header_name, header_value in malicious_headers.items():
            response = api_client.make_request(
                'POST',
                '/users/forget-password',
                data={'email': email},
                headers={header_name: header_value}
            )
            if header_value in response.text:
                vulnerabilities.append({
                    'type': 'Header Injection',
                    'severity': 'MEDIUM',
                    'description': f'Malicious header reflected in response: {header_name}',
                    'header': header_name,
                    'value': header_value
                })
        if vulnerabilities:
            pytest.fail(f"Header injection vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.owasp
    def test_forget_password_ssrf_vulnerabilities(self, api_client, test_data):
        token = test_data['tokens']['forget_password_token']
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
            test_case = {"email": payload}
            try:
                response = api_client.make_request(
                    'POST',
                    '/users/forget-password',
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
                        'field': 'email'
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
    def test_forget_password_error_handling_security(self, api_client, test_data):
        token = test_data['tokens']['forget_password_token']
        vulnerabilities = []
        error_test_cases = [
            "invalid json{",
            {"email": 123},
            {"email": []},
            {"email": {}},
            {},
            {"email": "A" * 10000 + "@example.com"},
            {"email": "\x00\x01\x02@example.com"},
            {"email": "'; DROP TABLE users; --@example.com"},
        ]
        for test_case in error_test_cases:
            try:
                if isinstance(test_case, str):
                    import requests
                    base_url = api_client._get_base_url()
                    if not base_url.endswith('/'):
                        base_url += '/'
                    url = base_url + 'users/forget-password'
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
                        '/users/forget-password',
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
