# oblique.py
# Advanced oblique SQL injection scanner combining all detection techniques

import time
import requests
import urllib3
import random
import statistics
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, List, Tuple, Optional, Union, Any
import json
import concurrent.futures
from datetime import datetime
import logging

# Import all detection modules
from time_based import AdvancedTimeBasedDetector, run_time_based_scan
from error_based import AdvancedErrorBasedDetector, run_error_based_scan
from boolean_based import AdvancedBooleanBasedDetector, run_boolean_based_scan
from nosql_injection import AdvancedNoSQLInjectionDetector, run_nosql_injection_scan
from user_agents import AdvancedUserAgentRotator
from payload_generator import EnhancedPayloadGenerator
from bypass import AdvancedWAFBypass, SmartWAFBypass

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration / constants ------------------------------------------------
DEFAULT_MAX_WORKERS = 8
DEFAULT_SCAN_TIMEOUT = 300  # 5 minutes
DEFAULT_CONFIDENCE_THRESHOLD = 0.7

# Scan strategies
SCAN_STRATEGIES = {
    'comprehensive': 'All techniques with deep scanning',
    'aggressive': 'All techniques with optimized speed',
    'stealthy': 'Slow and stealthy approach',
    'targeted': 'Focus on specific techniques',
    'quick': 'Rapid assessment with basic techniques'
}

# Technique priorities
TECHNIQUES = {
    'error_based': {
        'name': 'Error-Based SQLi',
        'description': 'Extract information via database errors',
        'speed': 'fast',
        'stealth': 'low',
        'effectiveness': 'high'
    },
    'boolean_based': {
        'name': 'Boolean-Based Blind SQLi',
        'description': 'Infer data from boolean conditions',
        'speed': 'medium',
        'stealth': 'medium',
        'effectiveness': 'high'
    },
    'time_based': {
        'name': 'Time-Based Blind SQLi',
        'description': 'Detect injections via timing delays',
        'speed': 'slow',
        'stealth': 'high',
        'effectiveness': 'medium'
    },
    'nosql': {
        'name': 'NoSQL Injection',
        'description': 'Target NoSQL databases',
        'speed': 'fast',
        'stealth': 'low',
        'effectiveness': 'medium'
    }
}

# --- Helper utilities --------------------------------------------------------
def merge_vulnerability_results(all_results: Dict[str, Any]) -> Dict[str, Any]:
    """Merge results from all techniques into comprehensive report."""
    merged = {
        'target': all_results.get('target', {}),
        'scan_start': None,
        'scan_duration': 0,
        'techniques_used': [],
        'vulnerabilities_found': [],
        'parameters_tested': set(),
        'confidence_score': 0.0,
        'risk_level': 'low',
        'technique_details': {}
    }
    
    # Collect all vulnerabilities and calculate overall metrics
    all_vulnerabilities = []
    total_confidence = 0.0
    technique_count = 0
    
    for tech_name, result in all_results.items():
        if tech_name == 'target':
            continue
            
        merged['techniques_used'].append(tech_name)
        merged['technique_details'][tech_name] = result
        
        # Extract vulnerabilities
        if result.get('vulnerable_parameters'):
            for vuln in result['vulnerable_parameters']:
                vuln['detection_technique'] = tech_name
                all_vulnerabilities.append(vuln)
        
        # Update parameters tested
        if 'parameters_tested' in result:
            merged['parameters_tested'].update(
                [p['parameter'] for p in result['parameters_tested'] if isinstance(p, dict)]
            )
        
        # Calculate overall confidence
        if result.get('vulnerability_count', 0) > 0:
            tech_confidence = result.get('confidence', 0) or max(
                [v.get('confidence', 0) for v in result.get('vulnerable_parameters', [])] or [0]
            )
            total_confidence += tech_confidence
            technique_count += 1
    
    # Calculate overall metrics
    merged['vulnerabilities_found'] = all_vulnerabilities
    merged['vulnerability_count'] = len(all_vulnerabilities)
    merged['parameters_tested_count'] = len(merged['parameters_tested'])
    
    if technique_count > 0:
        merged['confidence_score'] = total_confidence / technique_count
    else:
        merged['confidence_score'] = 0.0
    
    # Determine risk level
    if merged['vulnerability_count'] == 0:
        merged['risk_level'] = 'low'
    elif merged['vulnerability_count'] == 1:
        merged['risk_level'] = 'medium'
    elif merged['vulnerability_count'] <= 3:
        merged['risk_level'] = 'high'
    else:
        merged['risk_level'] = 'critical'
    
    return merged

def calculate_scan_parameters(strategy: str) -> Dict[str, Any]:
    """Calculate scan parameters based on strategy."""
    strategies = {
        'comprehensive': {
            'time_based': {'sample_size': 5, 'base_delay': 5},
            'error_based': {'sample_size': 4},
            'boolean_based': {'sample_size': 5},
            'nosql': {'sample_size': 4},
            'timeout_multiplier': 2.0,
            'parallel_workers': 6
        },
        'aggressive': {
            'time_based': {'sample_size': 3, 'base_delay': 3},
            'error_based': {'sample_size': 2},
            'boolean_based': {'sample_size': 3},
            'nosql': {'sample_size': 2},
            'timeout_multiplier': 0.7,
            'parallel_workers': 10
        },
        'stealthy': {
            'time_based': {'sample_size': 7, 'base_delay': 8},
            'error_based': {'sample_size': 3},
            'boolean_based': {'sample_size': 4},
            'nosql': {'sample_size': 3},
            'timeout_multiplier': 3.0,
            'parallel_workers': 3
        },
        'targeted': {
            'time_based': {'sample_size': 4, 'base_delay': 4},
            'error_based': {'sample_size': 3},
            'boolean_based': {'sample_size': 4},
            'nosql': {'sample_size': 3},
            'timeout_multiplier': 1.5,
            'parallel_workers': 8
        },
        'quick': {
            'time_based': {'sample_size': 2, 'base_delay': 2},
            'error_based': {'sample_size': 2},
            'boolean_based': {'sample_size': 2},
            'nosql': {'sample_size': 2},
            'timeout_multiplier': 0.5,
            'parallel_workers': 12
        }
    }
    
    return strategies.get(strategy, strategies['comprehensive'])

def prioritize_techniques(target: Dict[str, Any]) -> List[str]:
    """Prioritize techniques based on target characteristics."""
    techniques = ['error_based', 'boolean_based', 'time_based', 'nosql']
    
    # Analyze target to prioritize techniques
    url = target.get('url', '')
    method = target.get('method', 'GET')
    data = target.get('data')
    
    # Check for JSON data (prioritize NoSQL)
    if data and isinstance(data, (dict, list)):
        if any(isinstance(v, (dict, list)) for v in (data.values() if isinstance(data, dict) else data)):
            techniques.remove('nosql')
            techniques.insert(0, 'nosql')
    
    # Check for API endpoints (prioritize error-based)
    if any(api_indicator in url.lower() for api_indicator in ['/api/', '/json', '/rest', '/graphql']):
        techniques.remove('error_based')
        techniques.insert(0, 'error_based')
    
    # Check for modern frameworks (prioritize boolean-based)
    if any(fw_indicator in url.lower() for fw_indicator in ['/angular', '/react', '/vue', '/node']):
        techniques.remove('boolean_based')
        techniques.insert(0, 'boolean_based')
    
    return techniques

# --- Main Oblique Scanner ----------------------------------------------------
class AdvancedObliqueScanner:
    """
    Advanced Oblique SQL Injection Scanner combining all detection techniques.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.scan_strategy = self.config.get('scan_strategy', 'comprehensive')
        self.max_workers = self.config.get('max_workers', DEFAULT_MAX_WORKERS)
        self.scan_timeout = self.config.get('scan_timeout', DEFAULT_SCAN_TIMEOUT)
        self.confidence_threshold = self.config.get('confidence_threshold', DEFAULT_CONFIDENCE_THRESHOLD)
        self.enabled_techniques = self.config.get('enabled_techniques', ['error_based', 'boolean_based', 'time_based', 'nosql'])
        
        # Initialize components
        self.scan_parameters = calculate_scan_parameters(self.scan_strategy)
        self.ua_rotator = AdvancedUserAgentRotator()
        self.waf_bypass = AdvancedWAFBypass()
        
        # Logging
        self.logger = self._setup_logging()
        self.logger.info(f"Initialized oblique scanner with strategy: {self.scan_strategy}")

    def _setup_logging(self):
        logger = logging.getLogger('AdvancedObliqueScanner')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def _get_technique_config(self, technique: str) -> Dict[str, Any]:
        """Get configuration for specific technique."""
        base_config = {
            'detection_mode': 'advanced_bypass',
            'use_smart_bypass': True,
            'max_retries': 2,
            'confidence_threshold': self.confidence_threshold
        }
        
        # Add strategy-specific parameters
        tech_params = self.scan_parameters.get(technique, {})
        base_config.update(tech_params)
        
        return base_config

    def _run_technique_scan(self, technique: str, target: Dict[str, Any]) -> Dict[str, Any]:
        """Run scan for a specific technique."""
        self.logger.info(f"Starting {technique} scan...")
        
        try:
            tech_config = self._get_technique_config(technique)
            
            if technique == 'time_based':
                detector = AdvancedTimeBasedDetector(tech_config)
                result = detector.comprehensive_scan(target)
                detector.close()
                
            elif technique == 'error_based':
                detector = AdvancedErrorBasedDetector(tech_config)
                result = detector.comprehensive_scan(target)
                detector.close()
                
            elif technique == 'boolean_based':
                detector = AdvancedBooleanBasedDetector(tech_config)
                result = detector.comprehensive_scan(target)
                detector.close()
                
            elif technique == 'nosql':
                detector = AdvancedNoSQLInjectionDetector(tech_config)
                result = detector.comprehensive_scan(target)
                detector.close()
                
            else:
                result = {'error': f'Unknown technique: {technique}'}
            
            self.logger.info(f"Completed {technique} scan: {result.get('vulnerability_count', 0)} vulnerabilities")
            return result
            
        except Exception as e:
            self.logger.error(f"Error in {technique} scan: {e}")
            return {
                'error': str(e),
                'vulnerability_count': 0,
                'vulnerable_parameters': [],
                'parameters_tested': []
            }

    def _run_parallel_scans(self, target: Dict[str, Any], techniques: List[str]) -> Dict[str, Any]:
        """Run multiple technique scans in parallel."""
        all_results = {'target': target}
        scan_start = datetime.now()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, len(techniques))) as executor:
            # Submit all scan tasks
            future_to_tech = {
                executor.submit(self._run_technique_scan, tech, target): tech 
                for tech in techniques
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_tech):
                tech = future_to_tech[future]
                try:
                    result = future.result(timeout=self.scan_timeout)
                    all_results[tech] = result
                except concurrent.futures.TimeoutError:
                    self.logger.warning(f"{tech} scan timed out")
                    all_results[tech] = {'error': 'Scan timeout', 'vulnerability_count': 0}
                except Exception as e:
                    self.logger.error(f"{tech} scan failed: {e}")
                    all_results[tech] = {'error': str(e), 'vulnerability_count': 0}
        
        # Calculate total duration
        scan_duration = (datetime.now() - scan_start).total_seconds()
        all_results['scan_duration'] = scan_duration
        all_results['scan_start'] = scan_start
        
        return all_results

    def _run_sequential_scans(self, target: Dict[str, Any], techniques: List[str]) -> Dict[str, Any]:
        """Run technique scans sequentially."""
        all_results = {'target': target}
        scan_start = datetime.now()
        
        for tech in techniques:
            result = self._run_technique_scan(tech, target)
            all_results[tech] = result
            
            # Early termination if we found critical vulnerabilities
            if (result.get('vulnerability_count', 0) > 2 and 
                result.get('confidence', 0) > 0.9):
                self.logger.info(f"Early termination: Found critical vulnerabilities with {tech}")
                break
        
        scan_duration = (datetime.now() - scan_start).total_seconds()
        all_results['scan_duration'] = scan_duration
        all_results['scan_start'] = scan_start
        
        return all_results

    def comprehensive_scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive oblique scan using all techniques."""
        self.logger.info(f"Starting comprehensive oblique scan for {target.get('url')}")
        
        # Prioritize techniques based on target
        techniques = prioritize_techniques(target)
        
        # Filter enabled techniques
        techniques = [tech for tech in techniques if tech in self.enabled_techniques]
        
        self.logger.info(f"Using techniques: {', '.join(techniques)}")
        
        # Choose execution strategy based on scan strategy
        if self.scan_strategy in ['aggressive', 'quick']:
            all_results = self._run_parallel_scans(target, techniques)
        else:
            all_results = self._run_sequential_scans(target, techniques)
        
        # Merge results
        merged_results = merge_vulnerability_results(all_results)
        
        self._generate_scan_report(merged_results)
        return merged_results

    def targeted_scan(self, target: Dict[str, Any], specific_techniques: List[str] = None) -> Dict[str, Any]:
        """Perform targeted scan with specific techniques."""
        self.logger.info(f"Starting targeted oblique scan for {target.get('url')}")
        
        techniques = specific_techniques or ['error_based', 'boolean_based']
        techniques = [tech for tech in techniques if tech in self.enabled_techniques]
        
        if not techniques:
            techniques = ['error_based']  # Default fallback
        
        self.logger.info(f"Targeted techniques: {', '.join(techniques)}")
        
        all_results = self._run_parallel_scans(target, techniques)
        merged_results = merge_vulnerability_results(all_results)
        
        self._generate_scan_report(merged_results)
        return merged_results

    def adaptive_scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Perform adaptive scan that adjusts based on initial findings."""
        self.logger.info(f"Starting adaptive oblique scan for {target.get('url')}")
        
        # Start with fast techniques
        fast_techniques = ['error_based', 'nosql']
        fast_techniques = [tech for tech in fast_techniques if tech in self.enabled_techniques]
        
        self.logger.info("Phase 1: Fast techniques")
        phase1_results = self._run_parallel_scans(target, fast_techniques)
        
        # Check if we found vulnerabilities
        phase1_vulns = sum(
            result.get('vulnerability_count', 0) 
            for tech, result in phase1_results.items() 
            if tech != 'target'
        )
        
        if phase1_vulns > 0:
            self.logger.info(f"Found {phase1_vulns} vulnerabilities in phase 1, proceeding to phase 2")
            
            # Continue with slower techniques for confirmation
            slow_techniques = ['boolean_based', 'time_based']
            slow_techniques = [tech for tech in slow_techniques if tech in self.enabled_techniques]
            
            self.logger.info("Phase 2: Confirmation techniques")
            phase2_results = self._run_parallel_scans(target, slow_techniques)
            
            # Merge all results
            all_results = {'target': target}
            all_results.update(phase1_results)
            all_results.update(phase2_results)
        else:
            self.logger.info("No vulnerabilities found in phase 1, completing scan")
            all_results = phase1_results
        
        # Calculate total duration
        if 'scan_duration' in phase1_results:
            all_results['scan_duration'] = phase1_results['scan_duration']
            if 'scan_duration' in locals().get('phase2_results', {}):
                all_results['scan_duration'] += phase2_results['scan_duration']
        
        merged_results = merge_vulnerability_results(all_results)
        self._generate_scan_report(merged_results)
        
        return merged_results

    def quick_scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Perform quick assessment scan."""
        self.logger.info(f"Starting quick oblique scan for {target.get('url')}")
        
        # Use only fastest techniques
        quick_techniques = ['error_based', 'nosql']
        quick_techniques = [tech for tech in quick_techniques if tech in self.enabled_techniques]
        
        # Use aggressive parameters
        original_strategy = self.scan_strategy
        self.scan_strategy = 'quick'
        self.scan_parameters = calculate_scan_parameters('quick')
        
        all_results = self._run_parallel_scans(target, quick_techniques)
        
        # Restore original strategy
        self.scan_strategy = original_strategy
        self.scan_parameters = calculate_scan_parameters(original_strategy)
        
        merged_results = merge_vulnerability_results(all_results)
        self._generate_scan_report(merged_results)
        
        return merged_results

    def _generate_scan_report(self, scan_results: Dict[str, Any]):
        """Generate comprehensive scan report."""
        self.logger.info("=" * 70)
        self.logger.info("OBLIQUE SQL INJECTION SCAN REPORT")
        self.logger.info("=" * 70)
        self.logger.info(f"Target: {scan_results['target'].get('url')}")
        self.logger.info(f"Scan Strategy: {self.scan_strategy}")
        self.logger.info(f"Techniques Used: {', '.join(scan_results['techniques_used'])}")
        self.logger.info(f"Parameters Tested: {scan_results['parameters_tested_count']}")
        self.logger.info(f"Scan Duration: {scan_results.get('scan_duration', 0):.2f}s")
        self.logger.info(f"Overall Confidence: {scan_results['confidence_score']:.3f}")
        self.logger.info(f"Risk Level: {scan_results['risk_level'].upper()}")
        
        if scan_results['vulnerability_count'] > 0:
            self.logger.info("\nVULNERABILITIES FOUND:")
            self.logger.info("-" * 50)
            
            for i, vuln in enumerate(scan_results['vulnerabilities_found'], 1):
                self.logger.info(f"{i}. Parameter: {vuln['parameter']}")
                self.logger.info(f"   Technique: {vuln.get('detection_technique', 'Unknown')}")
                self.logger.info(f"   Confidence: {vuln.get('confidence', 0):.3f}")
                self.logger.info(f"   Database: {vuln.get('database_type', 'Unknown')}")
                
                # Show sample payloads
                successful_payloads = vuln.get('successful_payloads', [])
                if successful_payloads:
                    sample_payload = successful_payloads[0].get('payload', '')[:60]
                    self.logger.info(f"   Sample Payload: {sample_payload}...")
                self.logger.info("")
        else:
            self.logger.info("\nNo vulnerabilities found.")
        
        # Technique-specific summary
        self.logger.info("\nTECHNIQUE SUMMARY:")
        self.logger.info("-" * 30)
        for tech in scan_results['techniques_used']:
            tech_result = scan_results['technique_details'].get(tech, {})
            vuln_count = tech_result.get('vulnerability_count', 0)
            self.logger.info(f"{tech:15} : {vuln_count} vulnerabilities")
        
        self.logger.info("=" * 70)

    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics and capabilities."""
        return {
            'scan_strategy': self.scan_strategy,
            'max_workers': self.max_workers,
            'scan_timeout': self.scan_timeout,
            'confidence_threshold': self.confidence_threshold,
            'enabled_techniques': self.enabled_techniques,
            'scan_parameters': self.scan_parameters,
            'available_techniques': list(TECHNIQUES.keys()),
            'available_strategies': list(SCAN_STRATEGIES.keys())
        }

    def update_config(self, new_config: Dict[str, Any]):
        """Update scanner configuration."""
        self.config.update(new_config)
        
        if 'scan_strategy' in new_config:
            self.scan_strategy = new_config['scan_strategy']
            self.scan_parameters = calculate_scan_parameters(self.scan_strategy)
        
        if 'max_workers' in new_config:
            self.max_workers = new_config['max_workers']
        
        if 'scan_timeout' in new_config:
            self.scan_timeout = new_config['scan_timeout']
        
        if 'confidence_threshold' in new_config:
            self.confidence_threshold = new_config['confidence_threshold']
        
        if 'enabled_techniques' in new_config:
            self.enabled_techniques = new_config['enabled_techniques']
        
        self.logger.info("Scanner configuration updated")

# Convenience functions
def run_oblique_scan(target_config: Dict[str, Any], scan_type: str = 'comprehensive',
                    scanner_config: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Run oblique SQL injection scan with specified type.
    
    Args:
        target_config: Target configuration (url, method, data, etc.)
        scan_type: Type of scan ('comprehensive', 'targeted', 'adaptive', 'quick')
        scanner_config: Scanner configuration
    
    Returns:
        Comprehensive scan results
    """
    scanner = AdvancedObliqueScanner(scanner_config or {})
    
    try:
        if scan_type == 'comprehensive':
            return scanner.comprehensive_scan(target_config)
        elif scan_type == 'targeted':
            return scanner.targeted_scan(target_config)
        elif scan_type == 'adaptive':
            return scanner.adaptive_scan(target_config)
        elif scan_type == 'quick':
            return scanner.quick_scan(target_config)
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")
    
    except Exception as e:
        logging.error(f"Oblique scan failed: {e}")
        return {
            'error': str(e),
            'vulnerability_count': 0,
            'vulnerabilities_found': [],
            'risk_level': 'unknown'
        }

def get_scan_strategies():
    """Get available scan strategies."""
    return SCAN_STRATEGIES

def get_technique_info():
    """Get information about all available techniques."""
    return TECHNIQUES

def create_scan_profile(profile_name: str) -> Dict[str, Any]:
    """Create pre-configured scan profiles."""
    profiles = {
        'web_application': {
            'scan_strategy': 'comprehensive',
            'enabled_techniques': ['error_based', 'boolean_based', 'time_based'],
            'max_workers': 6,
            'confidence_threshold': 0.7
        },
        'api_endpoint': {
            'scan_strategy': 'targeted',
            'enabled_techniques': ['error_based', 'nosql'],
            'max_workers': 8,
            'confidence_threshold': 0.8
        },
        'stealth_scan': {
            'scan_strategy': 'stealthy',
            'enabled_techniques': ['boolean_based', 'time_based'],
            'max_workers': 3,
            'confidence_threshold': 0.9
        },
        'penetration_test': {
            'scan_strategy': 'aggressive',
            'enabled_techniques': ['error_based', 'boolean_based', 'time_based', 'nosql'],
            'max_workers': 10,
            'confidence_threshold': 0.6
        },
        'security_audit': {
            'scan_strategy': 'comprehensive',
            'enabled_techniques': ['error_based', 'boolean_based', 'time_based', 'nosql'],
            'max_workers': 4,
            'confidence_threshold': 0.85
        }
    }
    
    return profiles.get(profile_name, profiles['web_application'])

