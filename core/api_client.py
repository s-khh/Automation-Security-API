import json
import time
import logging
from typing import Dict, Any, Optional, List, Union
from urllib.parse import urljoin
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import yaml
from datetime import datetime, timedelta

class SecurityAPIClient:

    def __init__(self, config_path: str = "configs/config.yaml", env: str = "staging"):
        self.config = self._load_config(config_path)
        self.env = env
        self.session = self._create_session()
        self.logger = self._setup_logging()
        self.request_history = []
        self.rate_limit_tracker = {}

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        try:
            with open(config_path, 'r') as file:
                return yaml.safe_load(file)
        except FileNotFoundError:
            self.logger.error(f"Config file not found: {config_path}")
            return {}

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=self.config.get('base', {}).get('retry_attempts', 3),
            backoff_factor=self.config.get('base', {}).get('retry_delay', 1),
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def _get_base_url(self) -> str:
        return self.config.get('base', {}).get('api_url', 'https://stg-app.bosta.co/api/v2')

    def _get_default_headers(self) -> Dict[str, str]:
        headers = self.config.get('headers', {}).get('common', {}).copy()
        headers.update(self.config.get('headers', {}).get('security_headers', {}))
        return headers

    def _track_rate_limit(self, endpoint: str) -> bool:
        now = datetime.now()
        if endpoint not in self.rate_limit_tracker:
            self.rate_limit_tracker[endpoint] = []
        self.rate_limit_tracker[endpoint] = [
            req_time for req_time in self.rate_limit_tracker[endpoint]
            if now - req_time < timedelta(minutes=1)
        ]
        endpoint_mapping = {
            '/pickups': 'pickup',
            '/businesses/add-bank-info': 'bank_info', 
            '/users/forget-password': 'forget_password',
            '/users/generate-token-for-interview-task': 'token_generation'
        }
        config_key = endpoint_mapping.get(endpoint, endpoint)
        endpoint_config = self.config.get('endpoints', {}).get(config_key, {})
        rate_limit = endpoint_config.get('rate_limit', 60)
        if len(self.rate_limit_tracker[endpoint]) >= rate_limit:
            return False
        self.rate_limit_tracker[endpoint].append(now)
        return True

    def make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        auth_token: Optional[str] = None,
        bypass_rate_limit: bool = True,
        track_request: bool = True
    ) -> requests.Response:
        if not bypass_rate_limit and not self._track_rate_limit(endpoint):
            self.logger.warning(f"Rate limit exceeded for endpoint: {endpoint}")
            raise Exception(f"Rate limit exceeded for endpoint: {endpoint}")
        time.sleep(0.5)
        base_url = self._get_base_url()
        if not base_url.endswith('/'):
            base_url += '/'
        url = urljoin(base_url, endpoint.lstrip('/'))
        request_headers = self._get_default_headers()
        if headers:
            request_headers.update(headers)
        if auth_token:
            request_headers['Authorization'] = auth_token
        self.logger.info(f"Making {method} request to {url}")
        if data:
            self.logger.debug(f"Request data: {json.dumps(data, indent=2)}")
        start_time = time.time()
        try:
            self.logger.debug(f"Making {method.upper()} request to {url}")
            self.logger.debug(f"Headers: {request_headers}")
            self.logger.debug(f"Data: {data}")
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                headers=request_headers,
                params=params,
                timeout=self.config.get('base', {}).get('timeout', 30)
            )
            response_time = time.time() - start_time
            self.logger.debug(f"Response Status: {response.status_code}")
            self.logger.debug(f"Response Body: {response.text[:500]}...")
            if track_request:
                self._track_request(method, url, request_headers, data, response, response_time)
            self.logger.info(f"Response: {response.status_code} in {response_time:.2f}s")
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {str(e)}")
            raise

    def _track_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        data: Optional[Dict[str, Any]],
        response: requests.Response,
        response_time: float
    ):
        request_record = {
            'timestamp': datetime.now().isoformat(),
            'method': method,
            'url': url,
            'headers': headers,
            'data': data,
            'status_code': response.status_code,
            'response_time': response_time,
            'response_headers': dict(response.headers),
            'response_size': len(response.content)
        }
        if len(response.content) < 10000:
            try:
                request_record['response_content'] = response.json()
            except:
                request_record['response_content'] = response.text[:1000]
        self.request_history.append(request_record)

    def get_request_history(self) -> List[Dict[str, Any]]:
        return self.request_history

    def clear_request_history(self):
        self.request_history = []

    def analyze_response_for_vulnerabilities(self, response: requests.Response) -> List[Dict[str, Any]]:
        vulnerabilities = []
        if response.status_code == 200:
            try:
                response_data = response.json()
                sensitive_patterns = [
                    'password', 'token', 'secret', 'key', 'credential',
                    'ssn', 'social_security', 'credit_card', 'bank_account'
                ]
                response_text = json.dumps(response_data).lower()
                for pattern in sensitive_patterns:
                    if pattern in response_text:
                        vulnerabilities.append({
                            'type': 'Sensitive Data Exposure',
                            'severity': 'HIGH',
                            'description': f'Potential {pattern} exposure in response',
                            'pattern': pattern
                        })
            except:
                pass
        if response.status_code >= 400:
            if len(response.text) > 500:
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'MEDIUM',
                    'description': 'Verbose error message may leak system information',
                    'response_length': len(response.text)
                })
        security_headers = [
            'x-frame-options', 'x-content-type-options', 'x-xss-protection',
            'strict-transport-security', 'content-security-policy'
        ]
        missing_headers = []
        for header in security_headers:
            if header not in [h.lower() for h in response.headers.keys()]:
                missing_headers.append(header)
        if missing_headers:
            vulnerabilities.append({
                'type': 'Missing Security Headers',
                'severity': 'MEDIUM',
                'description': f'Missing security headers: {", ".join(missing_headers)}',
                'missing_headers': missing_headers
            })
        return vulnerabilities

    def test_sql_injection(self, endpoint: str, payload_field: str, auth_token: Optional[str] = None) -> List[Dict[str, Any]]:
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --",
            "'; WAITFOR DELAY '00:00:05' --"
        ]
        vulnerabilities = []
        for payload in sql_payloads:
            try:
                test_data = {payload_field: payload}
                response = self.make_request(
                    'POST', endpoint, data=test_data, auth_token=auth_token, track_request=False
                )
                error_patterns = [
                    'sql', 'mysql', 'postgresql', 'oracle', 'sqlite',
                    'syntax error', 'database error', 'query failed'
                ]
                response_text = response.text.lower()
                for pattern in error_patterns:
                    if pattern in response_text:
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'description': f'Potential SQL injection vulnerability detected',
                            'payload': payload,
                            'field': payload_field,
                            'evidence': pattern
                        })
                        break
            except Exception as e:
                self.logger.debug(f"SQL injection test failed: {str(e)}")
        return vulnerabilities

    def test_xss(self, endpoint: str, payload_field: str, auth_token: Optional[str] = None) -> List[Dict[str, Any]]:
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//",
            "<svg onload=alert('XSS')>"
        ]
        vulnerabilities = []
        for payload in xss_payloads:
            try:
                test_data = {payload_field: payload}
                response = self.make_request(
                    'POST', endpoint, data=test_data, auth_token=auth_token, track_request=False
                )
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'HIGH',
                        'description': 'XSS payload reflected in response',
                        'payload': payload,
                        'field': payload_field
                    })
            except Exception as e:
                self.logger.debug(f"XSS test failed: {str(e)}")
        return vulnerabilities