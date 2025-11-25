# error_based.py
# Advanced error-based SQLi detector with multiple detection modes

import time
import requests
import urllib3
import random
import re
import statistics
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

# Detection modes
DETECTION_MODES = {
    'basic': 'BasicDetectionPayloads only',
    'basic_bypass': 'BasicDetectionPayloads + WAF bypass',
    'advanced': 'AdvancedDetectionPayloads only', 
    'advanced_bypass': 'AdvancedDetectionPayloads + WAF bypass'
}

# Database-specific error patterns
ERROR_PATTERNS = {
    'mysql': [
        r"MySQL.*error",
        r"SQL syntax.*MySQL",
        r"Warning.*mysql",
        r"MySQL server",
        r"mysqli?_.*",
        r"SQLSTATE",
        r"1064",
        r"1146",
        r"1054",
        r"1241",
        r"1292"
    ],
    'postgresql': [
        r"PostgreSQL.*ERROR",
        r"ERROR.*PostgreSQL",
        r"PG.*error",
        r"SQLSTATE",
        r"column.*does not exist",
        r"relation.*does not exist",
        r"syntax error.*postgres",
        r"22P02",  # Invalid text representation
        r"42703",  # Undefined column
        r"42P01"   # Undefined table
    ],
    'mssql': [
        r"Microsoft.*SQL Server",
        r"SQL Server.*error",
        r"System\.Data\.SqlClient",
        r"Unclosed quotation mark",
        r"Incorrect syntax",
        r"Line \\d+",
        r"Msg \\d+",
        r"208",  # Invalid object name
        r"105",  # Unclosed quotation mark
        r"8152"  # String or binary data would be truncated
    ],
    'oracle': [
        r"ORA-\\d+",
        r"Oracle.*error",
        r"SQL.*Oracle",
        r"PLS-\\d+",
        r"ORA-01756",  # quoted string not properly terminated
        r"ORA-00933",  # SQL command not properly ended
        r"ORA-00904",  # invalid identifier
        r"ORA-00923",  # FROM keyword not found
        r"ORA-00936"   # missing expression
    ],
    'sqlite': [
        r"SQLite.*error",
        r"no such table",
        r"no such column",
        r"syntax error",
        r"near.*syntax error"
    ],
    'generic': [
        r"SQL.*error",
        r"SQL.*syntax",
        r"Database.*error",
        r"Warning.*sql",
        r"Fatal.*error",
        r"Uncaught.*Error",
        r"PDO.*Exception",
        r"SQLSTATE"
    ]
}

# --- Helper utilities --------------------------------------------------------
def extract_error_details(response_text: str, db_type: str = 'auto') -> Dict[str, Any]:
    """Extract error details from response text."""
    errors_found = []
    confidence = 0.0
    db_detected = 'unknown'
    
    # Test all database patterns
    for db, patterns in ERROR_PATTERNS.items():
        if db == 'generic' and db_detected != 'unknown':
            continue  # Skip generic if we already found specific
            
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                errors_found.extend(matches)
                if db != 'generic':
                    db_detected = db
                    confidence = max(confidence, 0.9)
                else:
                    confidence = max(confidence, 0.7)
    
    # Additional heuristic analysis
    if not errors_found:
        # Look for common error indicators
        error_indicators = [
            'error', 'exception', 'warning', 'fatal', 'invalid',
            'unexpected', 'syntax', 'undefined', 'null reference'
        ]
        
        indicator_count = sum(1 for indicator in error_indicators 
                            if indicator in response_text.lower())
        if indicator_count >= 2:
            confidence = 0.5
            errors_found = ['Heuristic error indicators detected']
    
    return {
        'errors': errors_found,
        'database_detected': db_detected,
        'confidence': confidence,
        'error_count': len(errors_found)
    }

def calculate_error_confidence(error_details: Dict[str, Any], baseline_errors: Dict[str, Any]) -> float:
    """Calculate confidence score for error-based detection."""
    if not error_details['errors']:
        return 0.0
    
    confidence = error_details['confidence']
    
    # Boost confidence for specific database errors
    if error_details['database_detected'] != 'unknown':
        confidence *= 1.2
    
    # Compare with baseline
    if baseline_errors and baseline_errors['error_count'] > 0:
        # If we get different errors than baseline, increase confidence
        baseline_error_set = set(baseline_errors['errors'])
        current_error_set = set(error_details['errors'])
        new_errors = current_error_set - baseline_error_set
        
        if new_errors:
            confidence += min(0.3, len(new_errors) * 0.1)
    
    return min(1.0, confidence)

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
class AdvancedErrorBasedDetector:
    """
    Enhanced Error-Based SQL Injection Detector with multiple detection modes.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.sample_size = self.config.get('sample_size', DEFAULT_SAMPLE_SIZE)
        self.confidence_threshold = self.config.get('confidence_threshold', DEFAULT_CONFIDENCE_THRESHOLD)
        self.max_response_time = self.config.get('max_response_time', 30)
        self.max_payloads_per_param = self.config.get('max_payloads_per_param', 25)
        self.detection_mode = self.config.get('detection_mode', 'advanced_bypass')
        self.use_smart_bypass = self.config.get('use_smart_bypass', False)
        self.payloads_directory = self.config.get('payloads_directory', 'payloads')

        # Initialize components based on detection mode
        self._initialize_components()
        
        # HTTP session
        self.http_session = ResilientHTTPSession(
            max_retries=self.config.get('max_retries', 3),
            backoff_factor=self.config.get('backoff_factor', 0.5)
        )

        # Internal state
        self.request_history: List[Dict[str, Any]] = []
        self.baseline_errors: Optional[Dict[str, Any]] = None
        self.learning_data = []

        # Logging
        self.logger = self._setup_logging()
        self.logger.info(f"Initialized error-based detector with mode: {self.detection_mode}")

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
        logger = logging.getLogger('AdvancedErrorBasedDetector')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    # ----------------- Enhanced Payload Management -------------------
    def _collect_error_payloads(self, db_hint: str = 'auto') -> List[Dict[str, Any]]:
        """
        Collect error-based payloads based on detection mode.
        """
        payloads = []
        
        if self.detection_mode in ['basic', 'basic_bypass']:
            payloads = self._get_basic_error_payloads(db_hint)
        else:
            payloads = self._get_advanced_error_payloads(db_hint)
        
        # Apply bypass if enabled in mode
        if self.detection_mode in ['basic_bypass', 'advanced_bypass']:
            payloads = self._apply_bypass_to_payloads(payloads)
        
        return payloads[:self.max_payloads_per_param]

    def _get_basic_error_payloads(self, db_hint: str) -> List[Dict[str, Any]]:
        """Get error-based payloads from BasicDetectionPayloads."""
        payloads = []
        pb = self.payload_source
        all_payloads = pb.get_all_payloads()
        
        # Get error-based payloads
        error_payloads = all_payloads.get('error_based', {})
        initial_payloads = all_payloads.get('basic_detection', [])
        
        # Process database-specific payloads
        db_priority = ['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite']
        if db_hint != 'auto' and db_hint in db_priority:
            db_priority = [db_hint] + [db for db in db_priority if db != db_hint]
        
        for db_type in db_priority:
            db_payloads = error_payloads.get(f'{db_type}_error', [])
            for p in db_payloads:
                processed = self._process_payload_template(p, db_type)
                if processed:
                    payloads.append({
                        'payload': processed,
                        'db': db_type,
                        'base_confidence': 0.85,
                        'description': f"{db_type} error-based",
                        'source': 'basic'
                    })
        
        # Add initial detection payloads
        for p in initial_payloads:
            payloads.insert(0, {
                'payload': p,
                'db': 'auto',
                'base_confidence': 0.7,
                'description': "Basic detection",
                'source': 'basic'
            })
        
        return payloads

    def _get_advanced_error_payloads(self, db_hint: str) -> List[Dict[str, Any]]:
        """Get error-based payloads from AdvancedDetectionPayloads."""
        payloads = []
        
        if not self.advanced_payloads:
            return self._get_basic_error_payloads(db_hint)
        
        # Get payloads by database type
        if db_hint != 'auto':
            db_payloads = self.advanced_payloads.get_payloads_by_database(db_hint)
        else:
            # Get all error-based payloads
            db_payloads = self.advanced_payloads.get_payloads_by_attack_type('error')
        
        # Flatten and process payloads
        for category, payload_list in db_payloads.items():
            for p in payload_list:
                if any(keyword in p.lower() for keyword in ['error', 'extractvalue', 'updatexml', 'convert', 'cast']):
                    processed = self._process_payload_template(p, db_hint)
                    if processed:
                        payloads.append({
                            'payload': processed,
                            'db': db_hint,
                            'base_confidence': 0.8,
                            'description': f"Advanced {category}",
                            'source': 'advanced'
                        })
        
        # Add basic payloads as fallback
        if not payloads:
            payloads = self._get_basic_error_payloads(db_hint)
        
        return payloads

    def _apply_bypass_to_payloads(self, original_payloads: List[Dict]) -> List[Dict]:
        """Apply WAF bypass techniques to payloads."""
        bypassed_payloads = []
        
        for original in original_payloads[:15]:  # Limit for performance
            raw_payload = original['payload']
            
            # Apply smart bypass if enabled
            if self.use_smart_bypass and self.smart_bypass:
                try:
                    smart_variants = self.smart_bypass.get_optimized_bypass(raw_payload, self.waf_bypass)
                    for variant in smart_variants[:2]:
                        bypassed_payloads.append({
                            'payload': variant,
                            'db': original['db'],
                            'base_confidence': original['base_confidence'] * 0.95,
                            'description': original['description'] + ' (smart bypass)',
                            'source': original['source'] + '_bypass'
                        })
                except Exception as e:
                    self.logger.debug(f"Smart bypass failed: {e}")
            
            # Apply standard bypass techniques
            try:
                bypass_variants = self.waf_bypass.apply_all_bypasses(raw_payload, max_variations=3)
                for variant in bypass_variants:
                    if variant not in [p['payload'] for p in bypassed_payloads]:
                        bypassed_payloads.append({
                            'payload': variant,
                            'db': original['db'],
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

    def _process_payload_template(self, payload: str, db_type: str) -> str:
        """Process payload templates with actual values."""
        processed = payload
        
        replacements = {
            '[RANDNUM]': str(random.randint(1000, 9999)),
            '[RANDSTR]': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8)),
        }
        
        for placeholder, value in replacements.items():
            processed = processed.replace(placeholder, value)
            
        return processed

    # ----------------- Baseline Measurement -------------------
    def calculate_baseline(self, url: str, method: str = 'GET', headers: Dict = None, 
                         data: Dict = None, cookies: Dict = None, samples: int = 3) -> Dict[str, Any]:
        """Measure baseline error response."""
        self.logger.info(f"Calculating baseline with {samples} samples for {url}")
        baseline_errors = {
            'errors': [],
            'database_detected': 'unknown',
            'confidence': 0.0,
            'error_count': 0
        }
        
        headers = self._prepare_headers(headers)
        all_error_details = []
        
        for i in range(samples):
            try:
                ok, response_text, sc, _ = self._send_request(url, method, headers=headers, 
                                                             data=data, cookies=cookies, safe_mode=True)
                if ok:
                    error_details = extract_error_details(response_text)
                    all_error_details.append(error_details)
                time.sleep(0.5 + random.random() * 0.5)
            except Exception as e:
                self.logger.debug(f"Baseline request {i+1} failed: {e}")
                continue

        if all_error_details:
            # Aggregate baseline errors
            all_errors = []
            for details in all_error_details:
                all_errors.extend(details['errors'])
            
            baseline_errors['errors'] = list(set(all_errors))
            baseline_errors['error_count'] = len(baseline_errors['errors'])
            
            # Determine most common database
            db_counts = {}
            for details in all_error_details:
                db = details['database_detected']
                if db != 'unknown':
                    db_counts[db] = db_counts.get(db, 0) + 1
            
            if db_counts:
                baseline_errors['database_detected'] = max(db_counts, key=db_counts.get)
        
        self.baseline_errors = baseline_errors
        self.logger.info(f"Baseline established: {baseline_errors['error_count']} error patterns")
        
        return baseline_errors

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
                     timeout: Optional[int] = None) -> Tuple[bool, str, int, str]:
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

            return True, response_text, resp.status_code, resp.headers.get('Content-Type', '')
            
        except requests.exceptions.Timeout:
            rt = time.time() - start
            self.logger.debug(f"Request timeout after {rt:.2f}s: {url}")
            return False, "Timeout", 0, ""
        except requests.RequestException as e:
            rt = time.time() - start
            self.logger.debug(f"Request failed: {e}")
            return False, str(e), 0, ""
        except Exception as e:
            rt = time.time() - start
            self.logger.debug(f"Unexpected error: {e}")
            return False, str(e), 0, ""

    # ----------------- Injection Helpers -------------------
    def _inject_into_structure(self, data_structure: Any, key: str, value: str):
        """Recursively inject payload into data structures."""
        if isinstance(data_structure, dict):
            for k, v in list(data_structure.items()):
                if k == key:
                    data_structure[k] = value
                else:
                    self._inject_into_structure(v, key, value)
        elif isinstance(data_structure, list):
            for i, item in enumerate(data_structure):
                if isinstance(item, (dict, list)):
                    self._inject_into_structure(item, key, value)

    def _inject_into_xml(self, xml_data: str, element: str, value: str) -> str:
        """Inject payload into XML data."""
        try:
            root = ET.fromstring(xml_data)
            for elem in root.iter(element):
                elem.text = value
            return ET.tostring(root, encoding='unicode')
        except Exception:
            return xml_data.replace(f"<{element}>", f"<{element}>{value}")

    # ----------------- Error Analysis -------------------
    def analyze_error_response(self, response_text: str, baseline_errors: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive error response analysis."""
        error_details = extract_error_details(response_text)
        confidence = calculate_error_confidence(error_details, baseline_errors)
        
        # Additional analysis
        response_length = len(response_text)
        has_server_error = any(str(code) in response_text for code in [500, 501, 502, 503])
        
        return {
            'error_details': error_details,
            'confidence': confidence,
            'response_length': response_length,
            'has_server_error': has_server_error,
            'is_vulnerable': confidence >= self.confidence_threshold
        }

    # ----------------- Core Testing Logic -------------------
    def _test_single_payload(self, test_url: str, method: str, headers: Dict, 
                           data: Any, cookies: Dict, payload: str) -> Dict[str, Any]:
        """Test a single payload with multiple samples."""
        error_results = []
        response_times = []
        
        for i in range(self.sample_size):
            try:
                start = time.time()
                ok, response_text, sc, content_type = self._send_request(
                    test_url, method, headers=headers, data=data, cookies=cookies
                )
                rt = time.time() - start
                response_times.append(rt)
                
                if ok and sc < 500:  # Only analyze successful requests
                    error_analysis = self.analyze_error_response(response_text, self.baseline_errors)
                    error_results.append(error_analysis)
                
                time.sleep(0.3 + random.random() * 0.3)
            except Exception as e:
                self.logger.debug(f"Test request {i+1} failed: {e}")
                continue

        # Aggregate results
        if error_results:
            max_confidence = max(result['confidence'] for result in error_results)
            avg_confidence = statistics.mean(result['confidence'] for result in error_results)
            vulnerable_count = sum(1 for result in error_results if result['is_vulnerable'])
        else:
            max_confidence = 0.0
            avg_confidence = 0.0
            vulnerable_count = 0

        return {
            'payload': payload,
            'error_results': error_results,
            'response_times': response_times,
            'max_confidence': max_confidence,
            'avg_confidence': avg_confidence,
            'vulnerable_samples': vulnerable_count,
            'total_samples': len(error_results)
        }

    def _build_test_request(self, url: str, method: str, headers: Dict, 
                          data: Any, parameter: str, payload: str) -> Tuple[str, str, Dict, Any]:
        """Build test request with injected payload."""
        test_url = url
        test_method = method
        test_headers = headers.copy()
        test_data = data.copy() if hasattr(data, 'copy') else data

        if method.upper() == 'GET':
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            query_params[parameter] = [payload]
            new_query = urlencode(query_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        else:
            content_type = test_headers.get('Content-Type', '')
            
            if 'application/json' in content_type:
                if isinstance(test_data, str):
                    try:
                        json_data = json.loads(test_data)
                        self._inject_into_structure(json_data, parameter, payload)
                        test_data = json.dumps(json_data)
                    except json.JSONDecodeError:
                        test_data = test_data.replace(f'"{parameter}"', f'"{payload}"')
                else:
                    self._inject_into_structure(test_data, parameter, payload)
                    
            elif 'xml' in content_type and isinstance(test_data, str):
                test_data = self._inject_into_xml(test_data, parameter, payload)
                
            elif isinstance(test_data, dict):
                test_data[parameter] = payload
                
            elif isinstance(test_data, str):
                test_data = test_data.replace(f"{parameter}=", f"{parameter}={payload}")

        return test_url, test_method, test_headers, test_data

    def test_parameter(self, url: str, parameter: str, value: str = 'test', 
                     method: str = 'GET', headers: Dict = None, data: Any = None, 
                     cookies: Dict = None, database_type: str = 'auto') -> Dict[str, Any]:
        """Test a specific parameter for error-based SQL injection."""
        self.logger.info(f"Testing parameter '{parameter}' with mode: {self.detection_mode}")
        
        headers = self._prepare_headers(headers)
        cookies = cookies or {}
        original_data = data.copy() if hasattr(data, 'copy') else data

        # Calculate baseline if not done
        if self.baseline_errors is None:
            self.calculate_baseline(url, method, headers, original_data, cookies)

        # Get payloads based on detection mode
        all_payloads = self._collect_error_payloads(database_type)
        
        self.logger.info(f"Testing {len(all_payloads)} error payload variants for parameter '{parameter}'")

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
                    test_data, cookies, pl['payload']
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
                        'error_results': result['error_results'],
                        'max_confidence': result['max_confidence'],
                        'avg_confidence': result['avg_confidence'],
                        'vulnerable_samples': result['vulnerable_samples'],
                        'total_samples': result['total_samples'],
                        'combined_confidence': combined_conf,
                        'detection_mode': self.detection_mode,
                        'vulnerable': False
                    }

                    if (combined_conf >= self.confidence_threshold and 
                        result['vulnerable_samples'] >= max(2, int(self.sample_size * 0.6))):
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
            'database_type': database_type,
            'vulnerable': len(vulnerable_payloads) > 0,
            'confidence': overall_confidence,
            'payloads_tested': len(results_details),
            'successful_payloads': vulnerable_payloads,
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
        """Perform comprehensive error-based SQL injection scan."""
        self.logger.info(f"Starting comprehensive error-based scan for {target.get('url')} with mode: {self.detection_mode}")
        
        if self.baseline_errors is None:
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

    def adaptive_scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Perform adaptive scan with quick first pass and deep follow-up."""
        self.logger.info(f"Starting adaptive error-based scan with mode: {self.detection_mode}")
        
        # Quick first pass
        original_sample_size = self.sample_size
        self.sample_size = max(2, self.sample_size // 2)
        
        quick_results = self.comprehensive_scan(target)
        
        # Restore original settings
        self.sample_size = original_sample_size

        if quick_results['vulnerability_count'] > 0:
            self.logger.info("Quick scan found potential vulnerabilities - performing deep verification")
            
            deep_results = {
                'target': target,
                'detection_mode': self.detection_mode,
                'parameters_tested': [],
                'vulnerable_parameters': []
            }
            
            for vuln_param in quick_results['vulnerable_parameters']:
                param_name = vuln_param['parameter']
                
                self.sample_size = min(5, self.sample_size * 2)
                
                try:
                    verified = self.test_parameter(
                        target['url'], param_name,
                        value=(target.get('data') or {}).get(param_name, 'test'),
                        method=target.get('method', 'GET'),
                        headers=target.get('headers'),
                        data=target.get('data'),
                        cookies=target.get('cookies'),
                        database_type='auto'
                    )
                    
                    deep_results['parameters_tested'].append(verified)
                    
                    if verified['vulnerable']:
                        deep_results['vulnerable_parameters'].append(verified)
                        
                finally:
                    self.sample_size = original_sample_size
            
            deep_results['vulnerability_count'] = len(deep_results['vulnerable_parameters'])
            return deep_results
        else:
            self.logger.info("No vulnerabilities found in quick scan - performing comprehensive scan")
            return self.comprehensive_scan(target)

    def _generate_scan_summary(self, scan_results: Dict[str, Any]):
        """Generate comprehensive scan summary."""
        self.logger.info("=" * 60)
        self.logger.info("ERROR-BASED SQL INJECTION SCAN SUMMARY")
        self.logger.info(f"Target: {scan_results['target'].get('url')}")
        self.logger.info(f"Detection mode: {scan_results['detection_mode']}")
        self.logger.info(f"Parameters tested: {len(scan_results['parameters_tested'])}")
        self.logger.info(f"Vulnerabilities found: {scan_results['vulnerability_count']}")
        self.logger.info(f"Scan duration: {scan_results.get('scan_duration', 0):.2f}s")
        
        if scan_results['vulnerability_count'] > 0:
            self.logger.info("Vulnerable parameters:")
            for vuln in scan_results['vulnerable_parameters']:
                self.logger.info(f"  - {vuln['parameter']} (confidence: {vuln['confidence']:.3f})")
                for successful in vuln.get('successful_payloads', [])[:2]:
                    self.logger.info(f"    Payload: {successful['payload'][:50]}...")
        
        self.logger.info("=" * 60)

    def close(self):
        """Clean up resources."""
        self.http_session.close()

# Convenience functions
def run_error_based_scan(target_config: Dict[str, Any], scan_type: str = 'comprehensive',
                        detector_config: Dict[str, Any] = None,
                        use_webdriver: bool = False,
                        custom_payloads: List[str] = None):

    enriched_target = target_config
    detector = AdvancedErrorBasedDetector(detector_config or {})

    try:
        if scan_type == 'quick':
            detector.sample_size = 2
            return detector.adaptive_scan(enriched_target)

        elif scan_type == 'comprehensive':
            return detector.comprehensive_scan(enriched_target)

        elif scan_type == 'adaptive':
            return detector.adaptive_scan(enriched_target)

        else:
            raise ValueError(f"Unknown scan type: {scan_type}")

    finally:
        detector.close()

def get_detection_modes():
    """Get available detection modes."""
    return DETECTION_MODES

def extract_database_info(error_text: str) -> Dict[str, Any]:
    """Extract database information from error messages."""
    return extract_error_details(error_text)