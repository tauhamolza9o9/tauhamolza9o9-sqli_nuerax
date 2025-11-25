# time_based.py
# Advanced time-based SQLi detector with multiple detection modes

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
import asyncio

# Import your modules
from user_agents import AdvancedUserAgentRotator
from payload_generator import BasicDetectionPayloads, AdvancedDetectionPayloads, EnhancedPayloadGenerator
from bypass import AdvancedWAFBypass, SmartWAFBypass, generate_smart_bypass_payloads

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration / constants ------------------------------------------------
DEFAULT_BASE_DELAY = 5
DEFAULT_SAMPLE_SIZE = 5
DEFAULT_CONFIDENCE_THRESHOLD = 0.8
MAX_PARALLEL_PAYLOADS = 6

# Detection modes
DETECTION_MODES = {
    'basic': 'BasicDetectionPayloads only',
    'basic_bypass': 'BasicDetectionPayloads + WAF bypass',
    'advanced': 'AdvancedDetectionPayloads only', 
    'advanced_bypass': 'AdvancedDetectionPayloads + WAF bypass'
}




# --- Helper utilities --------------------------------------------------------
def trimmed_mean(samples: List[float], trim_fraction: float = 0.25) -> float:
    """Compute trimmed mean (robust to outliers)."""
    if not samples:
        return 0.0
    s = sorted(samples)
    n = len(s)
    k = int(n * trim_fraction)
    trimmed = s[k:n - k] if n - 2 * k > 0 else s
    return statistics.mean(trimmed) if trimmed else statistics.mean(s)

def robust_std(samples: List[float]) -> float:
    """Median absolute deviation scaled to approximate standard deviation."""
    if not samples:
        return 0.0
    med = statistics.median(samples)
    mad = statistics.median([abs(x - med) for x in samples])
    return mad * 1.4826 if mad > 0 else 0.0

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
class AdvancedTimeBasedDetector:
    """
    Enhanced Time-Based SQL Injection Detector with multiple detection modes.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.base_delay = self.config.get('base_delay', DEFAULT_BASE_DELAY)
        self.sample_size = self.config.get('sample_size', DEFAULT_SAMPLE_SIZE)
        self.confidence_threshold = self.config.get('confidence_threshold', DEFAULT_CONFIDENCE_THRESHOLD)
        self.max_response_time = self.config.get('max_response_time', 30)
        self.max_payloads_per_param = self.config.get('max_payloads_per_param', 30)
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
        self.baseline_response_time: Optional[float] = None
        self.learning_data = []

        # Logging
        self.logger = self._setup_logging()
        self.logger.info(f"Initialized detector with mode: {self.detection_mode}")

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
        logger = logging.getLogger('AdvancedTimeBasedDetector')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    # ----------------- Enhanced Payload Management -------------------
    def _collect_time_payloads(self, db_hint: str = 'auto') -> List[Dict[str, Any]]:
        """
        Collect payloads based on detection mode.
        """
        payloads = []
        
        if self.detection_mode in ['basic', 'basic_bypass']:
            payloads = self._get_basic_payloads(db_hint)
        else:
            payloads = self._get_advanced_payloads(db_hint)
        
        # Apply bypass if enabled in mode
        if self.detection_mode in ['basic_bypass', 'advanced_bypass']:
            payloads = self._apply_bypass_to_payloads(payloads)
        
        return payloads[:self.max_payloads_per_param]

    def _get_basic_payloads(self, db_hint: str) -> List[Dict[str, Any]]:
        """Get payloads from BasicDetectionPayloads."""
        payloads = []
        pb = self.payload_source
        all_payloads = pb.get_all_payloads()
        
        # Get time-based payloads
        time_payloads = all_payloads.get('time_based_blind', {})
        initial_payloads = all_payloads.get('initial_time_based', [])
        
        # Process database-specific payloads
        db_priority = ['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite']
        if db_hint != 'auto' and db_hint in db_priority:
            db_priority = [db_hint] + [db for db in db_priority if db != db_hint]
        
        for db_type in db_priority:
            db_payloads = time_payloads.get(f'{db_type}_time', [])
            for p in db_payloads:
                processed = self._process_payload_template(p, db_type)
                if processed:
                    payloads.append({
                        'payload': processed,
                        'db': db_type,
                        'base_confidence': 0.85,
                        'description': f"{db_type} time-based",
                        'source': 'basic'
                    })
        
        # Add initial payloads
        for p in initial_payloads:
            processed = p.replace('5', str(min(3, self.base_delay)))
            payloads.insert(0, {
                'payload': processed,
                'db': 'auto',
                'base_confidence': 0.9,
                'description': "Initial time-based",
                'source': 'basic'
            })
        
        return payloads

    def _get_advanced_payloads(self, db_hint: str) -> List[Dict[str, Any]]:
        """Get payloads from AdvancedDetectionPayloads."""
        payloads = []
        
        if not self.advanced_payloads:
            return self._get_basic_payloads(db_hint)
        
        # Get payloads by database type
        if db_hint != 'auto':
            db_payloads = self.advanced_payloads.get_payloads_by_database(db_hint)
        else:
            # Get all time-based payloads
            db_payloads = self.advanced_payloads.get_payloads_by_attack_type('time')
        
        # Flatten and process payloads
        for category, payload_list in db_payloads.items():
            for p in payload_list:
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
            payloads = self._get_basic_payloads(db_hint)
        
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
            '[SLEEPTIME]': str(self.base_delay),
            '[SLEEPTIME]000000': str(self.base_delay * 100000),
            '[RANDNUM]': str(random.randint(1000, 9999)),
            '[RANDSTR]': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8)),
            '5': str(self.base_delay)
        }
        
        for placeholder, value in replacements.items():
            processed = processed.replace(placeholder, value)
            
        return processed

    # ----------------- Baseline Measurement -------------------
    def calculate_baseline(self, url: str, method: str = 'GET', headers: Dict = None, 
                         data: Dict = None, cookies: Dict = None, samples: int = 6) -> float:
        """Measure baseline response time with robustness."""
        self.logger.info(f"Calculating baseline with {samples} samples for {url}")
        response_times = []
        headers = self._prepare_headers(headers)
        
        for i in range(samples):
            try:
                start = time.time()
                ok, rt, sc, _ = self._send_request(url, method, headers=headers, 
                                                 data=data, cookies=cookies, safe_mode=True)
                if ok:
                    response_times.append(rt)
                time.sleep(0.3 + random.random() * 0.3)
            except Exception as e:
                self.logger.debug(f"Baseline request {i+1} failed: {e}")
                continue

        if not response_times:
            self.logger.warning("Baseline measurement failed; using fallback 1.0s")
            self.baseline_response_time = 1.0
        else:
            bm = trimmed_mean(response_times, trim_fraction=0.25)
            self.baseline_response_time = max(0.1, bm)
            self.logger.info(f"Baseline established: {self.baseline_response_time:.3f}s")

        return self.baseline_response_time

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
                     timeout: Optional[int] = None) -> Tuple[bool, float, int, str]:
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

            return True, rt, resp.status_code, resp.text
            
        except requests.exceptions.Timeout:
            rt = time.time() - start
            self.logger.debug(f"Request timeout after {rt:.2f}s: {url}")
            return False, rt, 0, "Timeout"
        except requests.RequestException as e:
            rt = time.time() - start
            self.logger.debug(f"Request failed: {e}")
            return False, rt, 0, str(e)
        except Exception as e:
            rt = time.time() - start
            self.logger.debug(f"Unexpected error: {e}")
            return False, rt, 0, str(e)

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

    # ----------------- Timing Analysis -------------------
    def analyze_timing_pattern(self, response_times: List[float], expected_delay: float) -> Dict[str, Any]:
        """Comprehensive timing analysis."""
        if not response_times:
            return {'confidence': 0.0, 'anomaly_score': 1.0, 'mean_response_time': 0.0, 
                    'std_dev': 0.0, 'delay_ratio': 0.0, 'samples': 0}

        mean_rt = trimmed_mean(response_times, 0.25)
        std_rt = robust_std(response_times) or (statistics.stdev(response_times) 
                     if len(response_times) > 1 else 0.0)
        
        delay_ratio = mean_rt / max(0.001, expected_delay)
        within_expected = sum(1 for r in response_times if r >= expected_delay * 0.7) / len(response_times)
        
        # Multi-factor confidence calculation
        confidence = 0.0
        
        # Factor 1: Delay ratio
        if delay_ratio >= 0.8:
            confidence += min(1.0, delay_ratio / 2.5) * 0.4

        # Factor 2: Response consistency
        confidence += within_expected * 0.3

        # Factor 3: Baseline comparison
        if self.baseline_response_time:
            ratio_to_base = mean_rt / self.baseline_response_time
            if ratio_to_base > 1.5:
                baseline_factor = min(1.0, (ratio_to_base - 1.5) / 3.0)
                confidence += baseline_factor * 0.3

        # Anomaly detection
        z_scores = [(r - mean_rt) / std_rt for r in response_times] if std_rt > 0 else [0] * len(response_times)
        anomaly_score = sum(1 for z in z_scores if abs(z) > 2.5) / len(z_scores)

        return {
            'confidence': min(1.0, confidence),
            'anomaly_score': anomaly_score,
            'mean_response_time': mean_rt,
            'std_dev': std_rt,
            'delay_ratio': delay_ratio,
            'samples': len(response_times)
        }

    # ----------------- Core Testing Logic -------------------
    def _test_single_payload(self, test_url: str, method: str, headers: Dict, 
                           data: Any, cookies: Dict, payload: str) -> Dict[str, Any]:
        """Test a single payload with multiple samples."""
        response_times = []
        
        for i in range(self.sample_size):
            ok, rt, sc, text = self._send_request(test_url, method, headers=headers, 
                                                data=data, cookies=cookies)
            if ok and sc < 500:
                response_times.append(rt)
            
            delay = 0.2 + (rt * 0.5 if ok else 0.5) + random.random() * 0.3
            time.sleep(delay)

        timing_analysis = self.analyze_timing_pattern(response_times, self.base_delay)
        
        return {
            'payload': payload,
            'response_times': response_times,
            'timing_analysis': timing_analysis
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
        """Test a specific parameter for time-based SQL injection."""
        self.logger.info(f"Testing parameter '{parameter}' with mode: {self.detection_mode}")
        
        headers = self._prepare_headers(headers)
        cookies = cookies or {}
        original_data = data.copy() if hasattr(data, 'copy') else data

        # Get payloads based on detection mode
        all_payloads = self._collect_time_payloads(database_type)
        
        self.logger.info(f"Testing {len(all_payloads)} payload variants for parameter '{parameter}'")

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
                    timing = result['timing_analysis']
                    
                    combined_conf = timing['confidence'] * pl['base_confidence']
                    
                    result_entry = {
                        'payload': pl['payload'],
                        'database_type': pl['db'],
                        'description': pl.get('description', ''),
                        'response_times': result['response_times'],
                        'timing_analysis': timing,
                        'combined_confidence': combined_conf,
                        'detection_mode': self.detection_mode,
                        'vulnerable': False
                    }

                    if (combined_conf >= self.confidence_threshold and 
                        timing['anomaly_score'] < 0.4 and 
                        len(result['response_times']) >= max(3, int(self.sample_size * 0.6))):
                        result_entry['vulnerable'] = True
                        vulnerable_payloads.append(result_entry)

                    results_details.append(result_entry)
                    
                    self.logger.info(
                        f"Payload tested: conf={timing['confidence']:.3f}, "
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
        """Perform comprehensive time-based SQL injection scan."""
        self.logger.info(f"Starting comprehensive scan for {target.get('url')} with mode: {self.detection_mode}")
        
        if self.baseline_response_time is None:
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
        self.logger.info(f"Starting adaptive scan with mode: {self.detection_mode}")
        
        # Quick first pass
        original_sample_size = self.sample_size
        original_delay = self.base_delay
        
        self.sample_size = max(3, self.sample_size // 2)
        self.base_delay = max(2, self.base_delay // 2)
        
        quick_results = self.comprehensive_scan(target)
        
        # Restore original settings
        self.sample_size = original_sample_size
        self.base_delay = original_delay

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
                
                self.sample_size = min(10, self.sample_size * 2)
                
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
        self.logger.info("TIME-BASED SQL INJECTION SCAN SUMMARY")
        self.logger.info(f"Target: {scan_results['target'].get('url')}")
        self.logger.info(f"Detection mode: {scan_results['detection_mode']}")
        self.logger.info(f"Parameters tested: {len(scan_results['parameters_tested'])}")
        self.logger.info(f"Vulnerabilities found: {scan_results['vulnerability_count']}")
        self.logger.info(f"Scan duration: {scan_results.get('scan_duration', 0):.2f}s")
        self.logger.info(f"Baseline response time: {self.baseline_response_time:.3f}s")
        
        if scan_results['vulnerability_count'] > 0:
            self.logger.info("Vulnerable parameters:")
            for vuln in scan_results['vulnerable_parameters']:
                self.logger.info(f"  - {vuln['parameter']} (confidence: {vuln['confidence']:.3f})")
        
        self.logger.info("=" * 60)

    def close(self):
        """Clean up resources."""
        self.http_session.close()

# Convenience functions
def run_time_based_scan(target_config: Dict[str, Any], scan_type: str = 'comprehensive',
                        detector_config: Dict[str, Any] = None,
                        use_webdriver: bool = False,
                        custom_payloads: List[str] = None):

    enriched_target = target_config
    detector = AdvancedTimeBasedDetector(detector_config or {})


    try:
        if scan_type == 'quick':
            detector.sample_size = 3
            detector.base_delay = 3
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

 