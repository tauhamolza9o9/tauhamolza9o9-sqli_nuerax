"""
utils.py — helpers for engine.py

Provides:
- logger factory
- resilient HTTP session (requests.Session with retry)
- payload & bypass instantiators (thin wrappers)
- common helpers: safe_request(), merge_scan_results(), save_report()
- utilities for injecting payloads into various data types
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Import payload/bypass classes from your repo
# engine.py must be able to import these modules (they are in attack_victor/*)
from payload_generator import BasicDetectionPayloads, AdvancedDetectionPayloads, EnhancedPayloadGenerator
from bypass import AdvancedWAFBypass, SmartWAFBypass

from config import (
    LOG_FORMAT, LOG_LEVEL, HTTP_VERIFY_SSL, HTTP_RETRY_TOTAL, HTTP_RETRY_BACKOFF,
    ENGINE_DEFAULTS
)


# ---------- logging ----------
def make_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    level = level or LOG_LEVEL
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger


# ---------- HTTP session / safe request ----------
def create_session(
    max_retries: int = HTTP_RETRY_TOTAL,
    backoff_factor: float = HTTP_RETRY_BACKOFF,
    timeout: int = ENGINE_DEFAULTS['timeout'],
    verify_ssl: bool = HTTP_VERIFY_SSL
) -> requests.Session:
    """
    Returns a requests.Session configured with retry/backoff and default headers.
    Detectors in your code use a ResilientHTTPSession pattern; this provides a
    simple shareable session for engine.py and subcomponents.
    """
    session = requests.Session()
    retry = Retry(total=max_retries, backoff_factor=backoff_factor,
                  status_forcelist=[429, 500, 502, 503, 504], allowed_methods=['GET', 'POST'])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # sensible default headers (detectors rotate UA as needed)
    session.headers.update({
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive'
    })
    # store defaults for convenience
    session.verify = verify_ssl
    session.request_timeout = timeout
    return session


def safe_request(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs
) -> Tuple[bool, str, int, dict]:
    """
    Perform request with safe default handling. Returns (ok, text, status_code, headers).
    - does not raise exceptions to callers; instead returns ok=False and error text.
    """
    timeout = kwargs.pop('timeout', getattr(session, 'request_timeout', 30))
    try:
        resp = session.request(method, url, timeout=timeout, allow_redirects=False, **kwargs)
        text = resp.text or ""
        return True, text, resp.status_code, dict(resp.headers)
    except Exception as e:
        # logger optional; engine should call make_logger() and log if desired
        return False, str(e), 0, {}


# ---------- payload / bypass factories ----------
def load_payload_generators(payloads_dir: Optional[str] = None, use_advanced: bool = True):
    """
    Return a dict of payload generator instances used by detectors.
    Matches the classes referenced in your detectors.
    """
    payloads_dir = payloads_dir or ENGINE_DEFAULTS['payloads_dir']
    basic = BasicDetectionPayloads()
    advanced = None
    enhanced = None

    try:
        advanced = AdvancedDetectionPayloads(payloads_dir) if use_advanced else None
    except Exception:
        advanced = None

    try:
        enhanced = EnhancedPayloadGenerator(payloads_dir=payloads_dir)
    except Exception:
        enhanced = None

    return {
        'basic': basic,
        'advanced': advanced,
        'enhanced': enhanced
    }


def create_bypass_engines(use_smart: bool = False):
    """
    Instantiate WAF bypass helpers. Detectors expect AdvancedWAFBypass and SmartWAFBypass.
    """
    waf = AdvancedWAFBypass()
    smart = SmartWAFBypass() if use_smart else None
    return {'waf': waf, 'smart': smart}


# ---------- result merge and utilities ----------
def merge_scan_results(all_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge results from multiple technique detectors into a single report structure.
    Mirrors the logic in oblique.py merge_vulnerability_results but simplified.
    """
    merged = {
        'target': all_results.get('target', {}),
        'scan_start': all_results.get('scan_start'),
        'scan_duration': all_results.get('scan_duration', 0),
        'techniques_used': [],
        'vulnerabilities_found': [],
        'parameters_tested': set(),
        'confidence_score': 0.0,
        'risk_level': 'low',
        'technique_details': {}
    }

    total_conf = 0.0
    tech_count = 0

    for tech, res in all_results.items():
        if tech == 'target':
            continue
        merged['techniques_used'].append(tech)
        merged['technique_details'][tech] = res

        # collect vulnerable params if present
        vp = res.get('vulnerable_parameters') or res.get('successful_payloads') or []
        for vuln in vp:
            # normalize minimal info
            entry = {
                'parameter': vuln.get('parameter') or vuln.get('payload', '')[:50],
                'confidence': vuln.get('confidence', vuln.get('max_confidence', 0.0)),
                'technique': tech,
                'details': vuln
            }
            merged['vulnerabilities_found'].append(entry)

        # parameters tested tracking
        params_tested = res.get('parameters_tested', [])
        if isinstance(params_tested, (list, set)):
            merged['parameters_tested'].update(params_tested)

        # confidence aggregation
        conf = res.get('confidence') or (max((v.get('confidence', 0.0) for v in vp), default=0.0))
        if conf:
            total_conf += conf
            tech_count += 1

    merged['vulnerability_count'] = len(merged['vulnerabilities_found'])
    merged['parameters_tested_count'] = len(merged['parameters_tested'])
    merged['confidence_score'] = (total_conf / tech_count) if tech_count > 0 else 0.0

    # risk level heuristic
    if merged['vulnerability_count'] == 0:
        merged['risk_level'] = 'low'
    elif merged['vulnerability_count'] == 1:
        merged['risk_level'] = 'medium'
    elif merged['vulnerability_count'] <= 3:
        merged['risk_level'] = 'high'
    else:
        merged['risk_level'] = 'critical'

    return merged


# ---------- IO ----------
def save_report(report: Dict[str, Any], filename: str = "scan_report.json") -> str:
    """
    Save JSON report to disk and return absolute path.
    """
    path = os.path.abspath(filename)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    return path


# ---------- small helpers ----------
def normalize_confidence(value: float) -> float:
    """Clamp confidence into [0.0, 1.0]"""
    try:
        v = float(value)
    except Exception:
        return 0.0
    return max(0.0, min(1.0, v))
