"""
config.py — central configuration for attack_victor engine

This file centralizes constants, default detection modes/strategies and database
hints used across detectors. Values are chosen to match and unify the defaults
found in your detector modules (union_based, stacked_queries, oblique, nosql, etc).
"""

from typing import Dict, List

# --- Global timeouts / concurrency / sample sizes ----------------------------
DEFAULT_TIMEOUT_SECONDS: int = 30
DEFAULT_MAX_WORKERS: int = 8
DEFAULT_SCAN_TIMEOUT_SECONDS: int = 300

# Per-technique defaults (fallbacks can be overridden by engine runtime config)
DEFAULT_SAMPLE_SIZE: int = 4
DEFAULT_CONFIDENCE_THRESHOLD: float = 0.8
DEFAULT_DELAY_BETWEEN_REQUESTS: float = 0.5
DEFAULT_BASE_DELAY_SECONDS: int = 5  # used for time-based detectors

# Threading / parallelism limits
MAX_PARALLEL_PAYLOADS: int = 8

# HTTP session defaults
HTTP_VERIFY_SSL: bool = False
HTTP_ALLOW_REDIRECTS: bool = False
HTTP_RETRY_TOTAL: int = 3
HTTP_RETRY_BACKOFF: float = 0.5

# Logging
LOG_LEVEL: str = "INFO"
LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# --- Detection modes / scan strategies --------------------------------------
DETECTION_MODES: Dict[str, str] = {
    'basic': 'Basic payloads only',
    'basic_bypass': 'Basic + WAF bypass',
    'advanced': 'Advanced payloads',
    'advanced_bypass': 'Advanced + WAF bypass'
}

SCAN_STRATEGIES: Dict[str, str] = {
    'comprehensive': 'All techniques with deep scanning',
    'aggressive': 'Speed optimized, less depth',
    'stealthy': 'Low and slow',
    'targeted': 'Only selected techniques',
    'quick': 'Fast surface assessment'
}

# --- Database / technique hints (mirrors parts of your modules) -------------
# (These are intended as defaults/lookup data — detectors can override)
UNION_SYNTAX = {
    'mysql': {'union_operator': 'UNION', 'comment_style': '--', 'requires_from': False},
    'postgresql': {'union_operator': 'UNION', 'comment_style': '--', 'requires_from': False},
    'mssql': {'union_operator': 'UNION', 'comment_style': '--', 'requires_from': False},
    'oracle': {'union_operator': 'UNION', 'comment_style': '--', 'requires_from': True, 'dual_table': 'FROM DUAL'},
    'sqlite': {'union_operator': 'UNION', 'comment_style': '--', 'requires_from': False}
}

STACKED_SUPPORT = {
    'mssql': {'enabled': True, 'query_separator': ';'},
    'mysql': {'enabled': True, 'query_separator': ';'},
    'postgresql': {'enabled': True, 'query_separator': ';'},
    'oracle': {'enabled': False, 'query_separator': ';'},
    'sqlite': {'enabled': True, 'query_separator': ';'}
}

NOSQL_DATABASES = {
    'mongodb': 'MongoDB', 'couchdb': 'CouchDB', 'cassandra': 'Cassandra',
    'redis': 'Redis', 'elasticsearch': 'Elasticsearch', 'dynamodb': 'DynamoDB'
}

# --- Files / payloads directory ------------------------------------------------
# engine.py may override this with user-specified directory.
DEFAULT_PAYLOADS_DIR = "payloads"

# --- Engine defaults ----------------------------------------------------------
ENGINE_DEFAULTS = {
    'timeout': DEFAULT_TIMEOUT_SECONDS,
    'max_workers': DEFAULT_MAX_WORKERS,
    'sample_size': DEFAULT_SAMPLE_SIZE,
    'confidence_threshold': DEFAULT_CONFIDENCE_THRESHOLD,
    'delay': DEFAULT_DELAY_BETWEEN_REQUESTS,
    'payloads_dir': DEFAULT_PAYLOADS_DIR
}
