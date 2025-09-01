import pytest
import json
import time
from typing import Dict, Any, List
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.api_client import SecurityAPIClient
from core.auth import AuthSecurityTester
from core.utils import SecurityPayloadGenerator

class TestPickupAPISecurity:
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
    @pytest.mark.auth
    def test_pickup_authentication_bypass(self, api_client, test_data):
        pickup_data = test_data['valid_data']['pickup']
        response = api_client.make_request(
            'POST',
            '/pickups',
            data=pickup_data
        )
        assert response.status_code in [401, 403], f"API should require authentication, got {response.status_code}"
   
    @pytest.mark.security
    @pytest.mark.auth
    def test_pickup_token_manipulation(self, api_client, auth_tester, test_data):
        original_token = test_data['tokens']['pickup_token']
        pickup_data = test_data['valid_data']['pickup']
        vulnerabilities = auth_tester.test_token_manipulation(original_token)
        for vuln in vulnerabilities:
            if vuln['type'] == 'Token Manipulation Accepted':
                pytest.fail(f"Token manipulation vulnerability: {vuln['description']}")
   
    @pytest.mark.security
    @pytest.mark.idor
    def test_pickup_idor_business_location(self, api_client, test_data, invalid_data):
        token = test_data['tokens']['pickup_token']
        base_data = test_data['valid_data']['pickup'].copy()
        vulnerabilities = []
        idor_payloads = invalid_data['idor_payloads']
        for payload in idor_payloads:
            test_data_copy = base_data.copy()
            test_data_copy['businessLocationId'] = payload
            response = api_client.make_request(
                'POST',
                '/pickups',
                data=test_data_copy,
                auth_token=token
            )
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'IDOR - Business Location Access',
                    'severity': 'HIGH',
                    'description': f'Able to access business location: {payload}',
                    'payload': payload
                })
        if vulnerabilities:
            pytest.fail(f"IDOR vulnerabilities found: {vulnerabilities}")
    
    @pytest.mark.security
    @pytest.mark.idor
    def test_pickup_idor_contact_person(self, api_client, test_data, invalid_data):
        token = test_data['tokens']['pickup_token']
        base_data = test_data['valid_data']['pickup'].copy()
        vulnerabilities = []
        idor_payloads = invalid_data['idor_payloads']
        for payload in idor_payloads:
            test_data_copy = base_data.copy()
            test_data_copy['contactPerson']['_id'] = payload
            response = api_client.make_request(
                'POST',
                '/pickups',
                data=test_data_copy,
                auth_token=token
            )
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'IDOR - Contact Person Access',
                    'severity': 'HIGH',
                    'description': f'Able to access contact person: {payload}',
                    'payload': payload
                })
        if vulnerabilities:
            pytest.fail(f"Contact Person IDOR vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.injection
    def test_pickup_sql_injection(self, api_client, test_data, invalid_data):
        token = test_data['tokens']['pickup_token']
        base_data = test_data['valid_data']['pickup'].copy()
        sql_payloads = invalid_data['sql_injection']
        vulnerable_fields = ['businessLocationId', 'numberOfParcels', 'creationSrc']
        vulnerabilities = []
        for field in vulnerable_fields:
            for payload in sql_payloads:
                test_data_copy = base_data.copy()
                if field == 'contactPerson':
                    test_data_copy['contactPerson']['name'] = payload
                else:
                    test_data_copy[field] = payload
                response = api_client.make_request(
                    'POST',
                    '/pickups',
                    data=test_data_copy,
                    auth_token=token
                )
                if response.status_code == 500:
                    response_text = response.text.lower()
                    sql_errors = ['sql', 'mysql', 'database', 'syntax error']
                    for error in sql_errors:
                        if error in response_text:
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'CRITICAL',
                                'description': f'SQL injection in field: {field}',
                                'payload': payload,
                                'field': field,
                                'evidence': error
                            })
                            break
        if vulnerabilities:
            pytest.fail(f"SQL injection vulnerabilities: {vulnerabilities}")
    
    @pytest.mark.security
    @pytest.mark.xss
    def test_pickup_xss_injection(self, api_client, test_data, invalid_data):
        token = test_data['tokens']['pickup_token']
        base_data = test_data['valid_data']['pickup'].copy()
        xss_payloads = invalid_data['xss_payloads']
        text_fields = ['creationSrc']
        vulnerabilities = []
        for field in text_fields:
            for payload in xss_payloads:
                test_data_copy = base_data.copy()
                if field == 'contactPerson.name':
                    test_data_copy['contactPerson']['name'] = payload
                elif field == 'contactPerson.email':
                    test_data_copy['contactPerson']['email'] = payload
                else:
                    test_data_copy[field] = payload
                response = api_client.make_request(
                    'POST',
                    '/pickups',
                    data=test_data_copy,
                    auth_token=token
                )
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'HIGH',
                        'description': f'XSS vulnerability in field: {field}',
                        'payload': payload,
                        'field': field
                    })
        if vulnerabilities:
            pytest.fail(f"XSS vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.rate_limit
    def test_pickup_rate_limiting(self, api_client, auth_tester, test_data):
        token = test_data['tokens']['pickup_token']
        pickup_data = test_data['valid_data']['pickup']
        vulnerabilities = auth_tester.test_brute_force_protection('/pickups')
        if vulnerabilities:
            for vuln in vulnerabilities:
                if vuln['type'] == 'Insufficient Rate Limiting':
                    pytest.fail(f"Rate limiting issue: {vuln['description']}")
   
    @pytest.mark.security
    @pytest.mark.owasp
    def test_pickup_business_logic_flaws(self, api_client, test_data, invalid_data):
        token = test_data['tokens']['pickup_token']
        base_data = test_data['valid_data']['pickup'].copy()
        vulnerabilities = []
        for negative_value in invalid_data['business_logic']['negative_values']:
            test_data_copy = base_data.copy()
            test_data_copy['numberOfParcels'] = str(negative_value)
            response = api_client.make_request(
                'POST',
                '/pickups',
                data=test_data_copy,
                auth_token=token
            )
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Business Logic Flaw',
                    'severity': 'MEDIUM',
                    'description': f'Accepted negative number of parcels: {negative_value}',
                    'payload': negative_value
                })
        for large_value in invalid_data['business_logic']['large_values']:
            test_data_copy = base_data.copy()
            test_data_copy['numberOfParcels'] = str(large_value)
            response = api_client.make_request(
                'POST',
                '/pickups',
                data=test_data_copy,
                auth_token=token
            )
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Business Logic Flaw',
                    'severity': 'MEDIUM',
                    'description': f'Accepted extremely large parcel count: {large_value}',
                    'payload': large_value
                })
        test_data_copy = base_data.copy()
        test_data_copy['scheduledDate'] = '2020-01-01'
        response = api_client.make_request(
            'POST',
            '/pickups',
            data=test_data_copy,
            auth_token=token
        )
        if response.status_code == 200:
            vulnerabilities.append({
                'type': 'Business Logic Flaw',
                'severity': 'MEDIUM',
                'description': 'Accepted past date for pickup scheduling',
                'payload': '2020-01-01'
            })
        if vulnerabilities:
            pytest.fail(f"Business logic vulnerabilities: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.data_exposure
    def test_pickup_sensitive_data_exposure(self, api_client, test_data):
        token = test_data['tokens']['pickup_token']
        pickup_data = test_data['valid_data']['pickup']
        response = api_client.make_request(
            'POST',
            '/pickups',
            data=pickup_data,
            auth_token=token
        )
        vulnerabilities = api_client.analyze_response_for_vulnerabilities(response)
        sensitive_exposure = [v for v in vulnerabilities if v['type'] == 'Sensitive Data Exposure']
        if sensitive_exposure:
            pytest.fail(f"Sensitive data exposure: {sensitive_exposure}")
   
    @pytest.mark.security
    @pytest.mark.critical
    def test_pickup_privilege_escalation(self, api_client, test_data):
        token = test_data['tokens']['pickup_token']
        admin_endpoints = [
            '/admin/pickups',
            '/businesses/all-pickups',
            '/internal/pickups',
            '/pickups/admin'
        ]
        vulnerabilities = []
        for endpoint in admin_endpoints:
            response = api_client.make_request(
                'GET',
                endpoint,
                auth_token=token
            )
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Privilege Escalation',
                    'severity': 'CRITICAL',
                    'description': f'Unauthorized access to admin endpoint: {endpoint}',
                    'endpoint': endpoint
                })
        if vulnerabilities:
            pytest.fail(f"Privilege escalation vulnerabilities: {vulnerabilities}")
    
    @pytest.mark.security
    @pytest.mark.slow
    def test_pickup_comprehensive_fuzzing(self, api_client, test_data, payload_generator):
        token = test_data['tokens']['pickup_token']
        base_data = test_data['valid_data']['pickup'].copy()
        vulnerabilities = []
        fuzzable_fields = [
            'businessLocationId', 'numberOfParcels', 'scheduledDate', 'creationSrc'
        ]
        for field in fuzzable_fields:
            fuzz_data = [
                payload_generator.generate_random_string(1000),
                payload_generator.generate_random_string(10000),
                *payload_generator.generate_boundary_values('string'),
                *payload_generator.generate_boundary_values('number'),
            ]
            for fuzz_payload in fuzz_data:
                test_data_copy = base_data.copy()
                test_data_copy[field] = fuzz_payload
                try:
                    response = api_client.make_request(
                        'POST',
                        '/pickups',
                        data=test_data_copy,
                        auth_token=token
                    )
                    if response.status_code == 500:
                        vulnerabilities.append({
                            'type': 'Server Error on Fuzzing',
                            'severity': 'MEDIUM',
                            'description': f'Server error when fuzzing field: {field}',
                            'field': field,
                            'payload_type': type(fuzz_payload).__name__
                        })
                except Exception as e:
                    vulnerabilities.append({
                        'type': 'Exception on Fuzzing',
                        'severity': 'LOW',
                        'description': f'Exception when fuzzing field {field}: {str(e)}',
                        'field': field
                    })
        if vulnerabilities:
            print(f"Fuzzing found potential issues: {vulnerabilities}")
   
    @pytest.mark.security
    @pytest.mark.owasp
    def test_pickup_ssrf_vulnerabilities(self, api_client, test_data):
        token = test_data['tokens']['pickup_token']
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
        base_pickup_data = test_data['valid_data']['pickup'].copy()
        for payload in ssrf_payloads:
            test_cases = [
                {
                    **base_pickup_data,
                    "contactPerson": {
                        **base_pickup_data["contactPerson"],
                        "email": payload
                    }
                },
                {
                    **base_pickup_data,
                    "contactPerson": {
                        **base_pickup_data["contactPerson"],
                        "name": payload
                    }
                },
                {
                    **base_pickup_data,
                    "businessLocationId": payload
                }
            ]
            for test_case in test_cases:
                try:
                    response = api_client.make_request(
                        'POST',
                        '/pickups',
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
                            'field': 'email' if payload in str(test_case.get('contactPerson', {}).get('email', '')) else 'other'
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
    def test_pickup_error_handling_security(self, api_client, test_data):
        token = test_data['tokens']['pickup_token']
        vulnerabilities = []
        error_test_cases = [
            "invalid json{",
            {"businessLocationId": 123},
            {"contactPerson": "not_an_object"},
            {"numberOfParcels": "not_a_number"},
            {},
            {"businessLocationId": "test"},
            {"businessLocationId": "A" * 10000},
            {"contactPerson": {"name": "B" * 10000}},
            {"contactPerson": {"name": "\x00\x01\x02"}},
            {"contactPerson": {"name": "'; DROP TABLE pickups; --"}},
        ]
        for test_case in error_test_cases:
            try:
                if isinstance(test_case, str):
                    import requests
                    base_url = api_client._get_base_url()
                    if not base_url.endswith('/'):
                        base_url += '/'
                    url = base_url + 'pickups'
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
                        '/pickups',
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

    def teardown_class(self):
        pass