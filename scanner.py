"""
JSLeakHunter — Scanner Engine v3.2
Smart detection based on 雪瞳 tool's logic
Fixed: minified JS detection (long line handling) + base64 false positive filtering
Enhanced: Context-aware crypto key detection (AES/DES with short variable names)
NEVER skip JS files - analyze everything
"""

import hashlib
import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

from patterns import (
    get_patterns, is_whitelisted, is_framework_internal,
    get_credential_keywords, get_secret_keywords,
    get_short_values, get_medium_values, get_long_values,
    get_credential_patterns, is_id_key_valid, is_credential_valid,
    is_short_value, is_medium_value, is_long_value,
    is_key_blacklisted, contains_chinese, is_camel_case,
)
from js_extractor import extract_js_files


HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8",
}

SKIP_EXTENSIONS = {
    'css', 'png', 'jpg', 'jpeg', 'svg', 'gif', 'webp', 'ico',
    'pdf', 'zip', 'rar', '7z', 'woff', 'woff2', 'ttf', 'eot',
    'mp3', 'mp4', 'avi', 'mov', 'webm', 'ogg',
}

JS_EXTENSIONS = {'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx'}

# Threshold for treating a line as "minified code" (single long line)
MINIFIED_LINE_THRESHOLD = 500


class Scanner:
    def __init__(self, config, on_log=None):
        self.config = config
        self.on_log = on_log or (lambda msg: None)
        self.findings = []
        self.seen_hashes = set()
        self.seen_urls = set()
        self.use_browser = config.get('use_browser', False)
        self.full_scan = config.get('full_scan', False)
        self.stats = {
            'files_total': 0,
            'files_scanned': 0,
            'files_skipped': 0,
            'regex_hits': 0,
            'ai_calls': 0,
            'ai_hits': 0,
            'duplicates_removed': 0,
        }

    def run(self, progress_callback=None):
        target = self.config['target']
        depth = self.config.get('depth', 2)
        has_ai = bool(self.config.get('api_key'))
        self.on_log(f"[*] Target: {target}")
        self.on_log(f"[*] Depth: {depth} | AI: {'ON' if has_ai else 'OFF'}")

        self.on_log("[*] Phase 1: Collecting JS files...")
        resp = self._fetch_page(target)
        if not resp:
            self.on_log("[-] Failed to fetch target page")
            return self.findings

        js_info, extract_stats = extract_js_files(
            html_content=resp.text,
            page_url=target,
            headers=self._get_headers(),
            use_browser=self.use_browser,
            depth=depth
        )

        self.on_log(f"  [+] Found {extract_stats['unique_urls']} unique JS files")
        all_js_urls = {info['url'] for info in js_info}

        self.on_log("  [*] Checking source maps...")
        source_map_urls, source_map_contents = self._check_source_maps(all_js_urls)
        self.on_log(f"  -> Found {len(source_map_urls)} source maps")

        self.on_log("  [*] Collecting inline scripts...")
        inline_scripts = self._collect_inline_scripts(target)
        self.on_log(f"  -> Found {len(inline_scripts)} inline scripts")

        self.seen_urls = set()
        self.stats['files_total'] = len(all_js_urls) + len(inline_scripts) + len(source_map_contents)
        self.on_log(f"[+] Total: {len(all_js_urls)} external JS + {len(inline_scripts)} inline + {len(source_map_contents)} source maps")

        if not all_js_urls and not inline_scripts and not source_map_contents:
            self.on_log("[-] No JavaScript found")
            return self.findings

        patterns = get_patterns()

        self.on_log("[*] Phase 2: Scanning external JS files...")
        scanned = 0
        for url in all_js_urls:
            scanned += 1
            if progress_callback:
                progress_callback(scanned, self.stats['files_total'], url.split('/')[-1][:50])
            short = url if len(url) < 90 else url[:87] + "..."
            self.on_log(f"[{scanned}/{self.stats['files_total']}] {short}")
            content = self._fetch_js(url)
            if not content or len(content.strip()) < 30:
                self.on_log(f"  -> Skipped (empty/too small)")
                self.stats['files_skipped'] += 1
                continue
            self._scan_content(content, url, patterns)

        if source_map_contents:
            self.on_log(f"[*] Phase 3: Scanning {len(source_map_contents)} source map(s)...")
            for map_url, sources in source_map_contents:
                for source_name, source_content in sources:
                    if len(source_content.strip()) < 50:
                        continue
                    source_label = f"{map_url} -> {source_name}"
                    self.on_log(f"  [map] {source_name[:60]}")
                    self._scan_content(source_content, source_label, patterns)

        self.on_log(f"[*] Phase 4: Scanning {len(inline_scripts)} inline scripts...")
        for idx, script_content in enumerate(inline_scripts):
            if len(script_content.strip()) < 50:
                continue
            inline_id = f"inline://script-{idx+1}"
            self.on_log(f"  [inline-{idx+1}] ({len(script_content)} chars)")
            self._scan_content(script_content, inline_id, patterns)

        self.on_log("[*] Phase 5: Deduplication and ranking...")
        before = len(self.findings)
        self.findings = self._dedup(self.findings)
        self.stats['duplicates_removed'] = before - len(self.findings)

        sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        self.findings.sort(key=lambda x: sev_order.get(x.get('severity', 'LOW'), 3))

        self._log_summary()
        if progress_callback:
            progress_callback(self.stats['files_total'], self.stats['files_total'], 'Done')

        return self.findings

    def _scan_content(self, content, source_url, patterns):
        regex_results = self._regex_precheck(content, source_url, patterns)

        if regex_results:
            self.stats['regex_hits'] += len(regex_results)
            self.on_log(f"  -> Regex: {len(regex_results)} suspicious patterns")
            for f in regex_results:
                self._add_finding(f)

        if self.config.get('api_key') and len(content.strip()) > 50:
            self.stats['ai_calls'] += 1
            full_scan = self.config.get('full_scan', False)
            if full_scan:
                self.on_log(f"  -> AI full scanning...")
            else:
                self.on_log(f"  -> AI analyzing...")
            try:
                from analyzer import AIAnalyzer
                analyzer = AIAnalyzer(
                    self.config['api_url'],
                    self.config['api_key'],
                    self.config['model'],
                    on_log=self.on_log
                )
                ai_results = analyzer.analyze(content, source_url, regex_results, full_scan=full_scan)
                if ai_results:
                    self.stats['ai_hits'] += len(ai_results)
                    self.on_log(f"  -> AI found {len(ai_results)} issues")
                    for f in ai_results:
                        self._add_finding(f)
                else:
                    self.on_log(f"  -> AI: no issues found")
            except Exception as e:
                self.on_log(f"  -> AI error: {str(e)[:100]}")

    def _regex_precheck(self, content, source_url, patterns):
        """
        Smart regex scan based on 雪瞳 tool's logic.
        Uses multiple detection strategies with comprehensive filtering.

        KEY FIX: For minified JS (long lines), we do NOT skip the entire line
        based on framework patterns. Instead, each match goes through
        _is_false_positive individually. This prevents real secrets from
        being missed just because __webpack_require__ appears on the same line.
        """
        results = []
        lines = content.split('\n')

        credential_keywords = get_credential_keywords()
        secret_keywords = get_secret_keywords()
        credential_patterns = get_credential_patterns()

        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if len(line_stripped) < 10:
                continue
            if line_stripped.startswith('//') or line_stripped.startswith('*') or line_stripped.startswith('/*'):
                continue

            is_long_line = len(line_stripped) >= MINIFIED_LINE_THRESHOLD

            # For SHORT lines only: skip entire line if it's a framework internal pattern
            # For LONG lines (minified code): do NOT skip — let each match be checked individually
            if not is_long_line:
                if is_framework_internal(line):
                    continue

                # Vue.js: keys = "camelCaseValue" — skip entire line (only for short lines)
                if re.search(r'keys\s*[:=]\s*["\'][a-zA-Z]+["\']', line):
                    value_match = re.search(r'keys\s*[:=]\s*["\']([a-zA-Z]+)["\']', line)
                    if value_match and is_camel_case(value_match.group(1)):
                        continue

            # Strategy 1: Pattern-based detection (cloud keys, tokens, etc.)
            pattern_results = self._detect_by_patterns(line, line_num, source_url, patterns)
            results.extend(pattern_results)

            # Strategy 2: Credential keyword detection (password = "xxx")
            credential_results = self._detect_credentials(line, line_num, source_url,
                                                          credential_keywords)
            results.extend(credential_results)

            # Strategy 3: Secret keyword detection (apiKey = "xxx", secret_key = "xxx")
            secret_results = self._detect_secrets(line, line_num, source_url,
                                                   secret_keywords)
            results.extend(secret_results)

            # Strategy 4: 雪瞳 credential patterns (3 modes)
            xuetong_credential_results = self._detect_xuetong_credentials(line, line_num, source_url,
                                                                          credential_patterns)
            results.extend(xuetong_credential_results)

            # Strategy 5: Context-aware crypto key detection (AES/DES with short variable names)
            crypto_key_results = self._detect_crypto_keys(line, line_num, source_url)
            results.extend(crypto_key_results)

        return results

    def _detect_crypto_keys(self, line, line_num, source_url):
        """
        Context-aware crypto key detection.
        Finds 16/24/32 char string literals that are near AES/encrypt/decrypt operations.
        This catches patterns like: var r="EEOMv762enZKsCry" ... AES.encrypt(...)
        """
        results = []

        # Crypto context keywords that indicate encryption operations nearby
        crypto_keywords = [
            'AES', 'DES', 'Blowfish', 'RSA', 'HMAC',
            'encrypt', 'decrypt', 'Encrypt', 'Decrypt',
            'enc.Utf8', 'enc.Hex', 'enc.Base64',
            'ECB', 'CBC', 'CTR', 'GCM', 'CFB', 'OFB',
            'Pkcs7', 'Pkcs5', 'ZeroPadding',
            'CryptoJS', 'crypto-js', 'Cipher',
            'mode.ECB', 'mode.CBC',
        ]

        # Find all string literals of exactly 16, 24, or 32 alphanumeric chars
        pattern = r'''["']([A-Za-z0-9]{16})["']|["']([A-Za-z0-9]{24})["']|["']([A-Za-z0-9]{32})["']'''

        for match in re.finditer(pattern, line):
            value = match.group(1) or match.group(2) or match.group(3)
            if not value:
                continue

            # Check for crypto context within 500 chars of the match
            context_start = max(0, match.start() - 500)
            context_end = min(len(line), match.end() + 500)
            context = line[context_start:context_end]

            has_crypto_context = any(kw in context for kw in crypto_keywords)

            if has_crypto_context:
                key_len = len(value)

                # Skip if the value is a common non-secret string
                value_lower = value.lower()
                if is_short_value(value_lower) or is_medium_value(value_lower) or is_long_value(value_lower):
                    continue

                line_stripped = line.strip()
                if len(line_stripped) > 500:
                    evidence_start = max(0, match.start() - 30)
                    evidence_end = min(len(line_stripped), match.end() + 30)
                    evidence = "..." + line_stripped[evidence_start:evidence_end] + "..."
                else:
                    evidence = line_stripped[:300]

                results.append({
                    'url': source_url,
                    'line': line_num,
                    'type': f'AES/DES Encryption Key ({key_len} chars)',
                    'severity': 'HIGH',
                    'evidence': evidence,
                    'context': line_stripped[:200],
                    'recommendation': f'Verify this {key_len}-char encryption key and remove/move to environment variables',
                    'source': 'regex',
                    'confidence': 0.85,
                    'category': 'crypto',
                })

        return results

    def _detect_by_patterns(self, line, line_num, source_url, patterns):
        """Detect using predefined patterns with 雪瞳-style filtering"""
        results = []

        for p in patterns:
            try:
                m = re.search(p['pattern'], line, re.IGNORECASE)
            except Exception:
                continue
            if not m:
                continue

            matched_text = m.group(0)

            if is_whitelisted(matched_text):
                continue

            # For idkey category patterns (key1/key2 from 雪瞳), apply special validation
            if p['category'] == 'idkey':
                if not is_id_key_valid(matched_text):
                    continue

            if self._is_false_positive(matched_text, line, p, m, line_num):
                continue

            line_stripped = line.strip()
            if len(line_stripped) > 500:
                match_start = max(0, m.start() - 50)
                match_end = min(len(line_stripped), m.end() + 100)
                evidence = "..." + line_stripped[match_start:match_end] + "..."
            else:
                evidence = line_stripped[:300]

            results.append({
                'url': source_url,
                'line': line_num,
                'type': p['label'],
                'severity': p['severity'],
                'evidence': evidence,
                'context': line_stripped[:200],
                'recommendation': f"Verify this {p['label'].lower()} and remove/move to environment variables if confirmed",
                'source': 'regex',
                'confidence': p['confidence'],
                'category': p['category'],
            })

        return results

    def _detect_credentials(self, line, line_num, source_url, keywords):
        """
        Detect credential patterns with 雪瞳-style value filtering.
        Pattern: password = "value" or secret: "value"
        """
        results = []

        keywords_pattern = '|'.join(keywords)
        pattern = r'(?:' + keywords_pattern + r')[\w_-]*\s*[:=]\s*[\'"]([^\'"\,\s\(\)]{4,})[\'"]'

        for match in re.finditer(pattern, line, re.IGNORECASE):
            value = match.group(1)

            if len(value) <= 1:
                continue

            value_lower = value.lower()

            # Extract var name first for camelCase check
            var_match = re.search(r'([\w-]*(?:' + keywords_pattern + r')[\w_-]*)', line[:match.start()], re.IGNORECASE)
            var_name = var_match.group(1) if var_match else ''

            # 雪瞳核心逻辑：当变量名包含 "key" 且值是驼峰命名时，跳过
            if 'key' in var_name.lower() and is_camel_case(value):
                continue

            # 雪瞳-style value filtering
            if len(value) < 12 and is_short_value(value_lower):
                continue
            if len(value) < 16 and is_medium_value(value_lower):
                continue
            if is_long_value(value_lower):
                continue

            # Skip Chinese text values
            if contains_chinese(value):
                continue

            # Skip variable references (not string literals)
            if not match.group(0).startswith('"') and not match.group(0).startswith("'"):
                rest = line[match.end():match.end()+20].strip()
                if rest and rest[0] in ('+', ',', ';', ')', '}'):
                    continue

            # Skip if the key name is blacklisted
            if is_key_blacklisted(var_name):
                continue

            line_stripped = line.strip()
            results.append({
                'url': source_url,
                'line': line_num,
                'type': f'Credential ({var_name})',
                'severity': 'HIGH',
                'evidence': f'{var_name} = "{value}"',
                'context': line_stripped[:200],
                'recommendation': 'Verify this credential and remove/move to environment variables',
                'source': 'regex',
                'confidence': 0.85,
                'category': 'credential',
            })

        return results

    def _detect_secrets(self, line, line_num, source_url, keywords):
        """
        Detect secret patterns with 雪瞳-style value filtering.
        Pattern: secret_key = "value" or apiKey: "value"
        """
        results = []

        keywords_pattern = '|'.join(keywords)
        pattern = r'[\w-]*(?:' + keywords_pattern + r')[\w_-]*\s*[:=]\s*[\'"]([^\'"\,\s\(\)]{6,})[\'"]'

        for match in re.finditer(pattern, line, re.IGNORECASE):
            value = match.group(1)

            if len(value) <= 1:
                continue

            value_lower = value.lower()

            # Extract var name first for camelCase check
            var_match = re.search(r'([\w-]*(?:' + keywords_pattern + r')[\w_-]*)', line[:match.start()], re.IGNORECASE)
            var_name = var_match.group(1) if var_match else ''

            # 雪瞳核心逻辑：当变量名包含 "key" 且值是驼峰命名时，跳过
            if 'key' in var_name.lower() and is_camel_case(value):
                continue

            # 雪瞳-style value filtering
            if len(value) < 16 and is_short_value(value_lower):
                continue
            if len(value) < 16 and is_medium_value(value_lower):
                continue
            if is_long_value(value_lower):
                continue

            # Skip Chinese text values
            if contains_chinese(value):
                continue

            # Skip pure alphabetic short values
            if re.match(r'^[a-zA-Z]+$', value) and len(value) < 10:
                continue

            # Skip if the key name is blacklisted
            if is_key_blacklisted(var_name):
                continue

            line_stripped = line.strip()
            results.append({
                'url': source_url,
                'line': line_num,
                'type': f'Secret ({var_name})',
                'severity': 'HIGH',
                'evidence': f'{var_name} = "{value}"',
                'context': line_stripped[:200],
                'recommendation': 'Verify this secret and remove/move to environment variables',
                'source': 'regex',
                'confidence': 0.80,
                'category': 'secret',
            })

        return results

    def _detect_xuetong_credentials(self, line, line_num, source_url, credential_patterns):
        """
        Detect credentials using 雪瞳's 3-mode credential patterns.
        With proper validation based on 雪瞳's L.credentials logic.
        """
        results = []

        for cp in credential_patterns:
            try:
                for match in re.finditer(cp['pattern'], line, cp['flags']):
                    matched_text = match.group(0)

                    # Apply 雪瞳's credential validation
                    if not is_credential_valid(matched_text):
                        continue

                    if is_whitelisted(matched_text):
                        continue

                    # Extract key and value for display
                    parts = re.split(r'\s*[:=]\s*', matched_text.strip(), maxsplit=1)
                    if len(parts) < 2:
                        continue

                    key_name = parts[0].strip('"\'').strip()
                    value = parts[1].strip('"\'').strip()

                    # Skip if value is too short after cleanup
                    if len(value) < 4:
                        continue

                    line_stripped = line.strip()
                    results.append({
                        'url': source_url,
                        'line': line_num,
                        'type': f'Credential ({key_name})',
                        'severity': 'HIGH',
                        'evidence': f'{key_name} = "{value}"',
                        'context': line_stripped[:200],
                        'recommendation': 'Verify this credential and remove/move to environment variables',
                        'source': 'regex',
                        'confidence': 0.85,
                        'category': 'credential',
                    })
            except Exception:
                continue

        return results

    def _is_false_positive(self, matched_text, full_line, pattern, match_obj, line_num):
        """
        Smart false positive detection based on 雪瞳's logic.
        MINIMAL filtering - only clear false positives.
        This is called per-match, so it's safe for long (minified) lines.
        """
        if not matched_text:
            return False

        lower = matched_text.lower()
        line_lower = full_line.lower()

        # 1. Vue.js/React internal property assignments
        framework_patterns = [
            r'e\.key\s*=\s*t\.key',
            r'e\.isStatic\s*=\s*t\.isStatic',
            r'e\.isComment\s*=\s*t\.isComment',
        ]
        for fp in framework_patterns:
            if re.search(fp, full_line):
                return True

        # 2. Variable assignment (e.key = t.key)
        if re.search(r'[a-zA-Z_$]\.[a-zA-Z_$]*\.key\s*=\s*[a-zA-Z_$]\.', full_line):
            return True

        # 3. Check if value is variable reference (not string literal)
        value_part = full_line[match_obj.end():match_obj.end()+50].strip()
        if value_part and value_part[0] == '=':
            rest = value_part[1:].strip()
            if rest and re.match(r'^[a-zA-Z_$]', rest) and not re.match(r'^[\'"]', rest):
                return True

        # 4. Public CDN domains for infra category
        if pattern['category'] == 'infra':
            public_domains = [
                'googleapis.com', 'gstatic.com', 'cloudflare.com',
                'amazonaws.com', 'akamaized.net', 'cloudfront.net',
                'jsdelivr.net', 'unpkg.com', 'cdnjs.com', 'github.com',
            ]
            for d in public_domains:
                if d in lower:
                    return True

        # 5. URL key too short
        if pattern['category'] == 'url':
            value_match = re.search(r'(?:key|token|secret)=([A-Za-z0-9_\-]+)', full_line)
            if value_match:
                value = value_match.group(1)
                if len(value) < 10:
                    return True

        # 6. Obvious placeholders
        obvious_placeholders = [
            'your_key_here', 'your_secret_here',
            'example', 'test123', 'changeme', 'placeholder',
            'xxxxxxxxxxxxxxxx', '0000000000000000',
        ]
        for placeholder in obvious_placeholders:
            if lower == placeholder:
                return True

        # 7. 雪瞳: Skip if value contains common non-secret words (for token category)
        if pattern['category'] == 'token':
            token_value_match = re.search(r'[\'"]?([^\'"\s,;}{\)]{20,})[\'"]?', full_line)
            if token_value_match:
                token_val = token_value_match.group(1).lower()
                if is_medium_value(token_val):
                    return True
                if is_long_value(token_val):
                    return True

        # 8. Base64/font data false positive detection
        match_start = match_obj.start()
        match_end = match_obj.end()
        ctx_before = full_line[max(0, match_start - 80):match_start]
        ctx_after = full_line[match_end:min(len(full_line), match_end + 80)]
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= \r\n')
        if len(ctx_before) > 30 and all(c in base64_chars for c in ctx_before):
            return True
        if len(ctx_after) > 30 and all(c in base64_chars for c in ctx_after):
            return True

        # 9. Skip matches inside data: URLs (font/image base64 inline data)
        data_marker_pos = full_line.rfind('base64,', 0, match_start)
        if data_marker_pos == -1:
            data_marker_pos = full_line.rfind('data:', 0, match_start)
        if data_marker_pos != -1 and match_start - data_marker_pos < 500:
            between = full_line[data_marker_pos:match_start]
            if '"' not in between and "'" not in between and '\n' not in between:
                return True

        # 10. Vue.js: keys = "camelCaseValue" (per-match check for long lines)
        match_start_ctx = max(0, match_obj.start() - 20)
        match_end_ctx = min(len(full_line), match_obj.end() + 20)
        context = full_line[match_start_ctx:match_end_ctx]
        if re.search(r'keys\s*[:=]\s*["\'][a-zA-Z]+["\']', context):
            vm = re.search(r'keys\s*[:=]\s*["\']([a-zA-Z]+)["\']', context)
            if vm and is_camel_case(vm.group(1)):
                return True

        return False

    def _add_finding(self, finding):
        evidence_clean = re.sub(r'[\s"\':=\n\r]', '', finding.get('evidence', ''))[:60]
        content_hash = hashlib.md5(
            f"{finding.get('url','')}:{finding.get('line',0)}:{evidence_clean}".encode()
        ).hexdigest()

        if content_hash not in self.seen_hashes:
            self.seen_hashes.add(content_hash)
            self.findings.append(finding)

    def _dedup(self, findings):
        evidence_map = {}
        for f in findings:
            evidence_key = re.sub(r'[\s"\':=\n\r]', '', f.get('evidence', ''))[:60]
            if evidence_key not in evidence_map:
                evidence_map[evidence_key] = f
            else:
                existing = evidence_map[evidence_key]
                sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
                if sev_order.get(f.get('severity', 'LOW'), 3) < sev_order.get(existing.get('severity', 'LOW'), 3):
                    evidence_map[evidence_key] = f
                elif sev_order.get(f.get('severity', 'LOW'), 3) == sev_order.get(existing.get('severity', 'LOW'), 3):
                    if f.get('confidence', 0) > existing.get('confidence', 0):
                        evidence_map[evidence_key] = f
        return list(evidence_map.values())

    def _check_source_maps(self, js_urls):
        map_urls = []
        map_contents = []
        def check_one(js_url):
            map_url = js_url + '.map'
            try:
                resp = requests.get(map_url, headers=self._get_headers(), timeout=10, verify=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if 'sourcesContent' in data or 'sources' in data:
                            return map_url, data
                    except json.JSONDecodeError:
                        pass
            except:
                pass
            return None, None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_one, url): url for url in js_urls}
            for future in as_completed(futures):
                map_url, data = future.result()
                if data:
                    map_urls.append(map_url)
                    sources = []
                    contents = data.get('sourcesContent', [])
                    names = data.get('sources', [])
                    for i, content in enumerate(contents):
                        if content and isinstance(content, str) and len(content.strip()) > 20:
                            name = names[i] if i < len(names) else f'source-{i}'
                            sources.append((name, content))
                    if sources:
                        map_contents.append((map_url, sources))
        return map_urls, map_contents

    def _collect_inline_scripts(self, target_url):
        resp = self._fetch_page(target_url)
        if not resp:
            return []
        soup = BeautifulSoup(resp.text, 'html.parser')
        scripts = []
        for tag in soup.find_all('script', src=False):
            content = tag.string or tag.get_text()
            if content and len(content.strip()) >= 50:
                stripped = content.strip()
                if stripped.startswith('{') and '"@context"' in stripped:
                    continue
                scripts.append(content)
        return scripts

    def _fetch_js(self, url):
        try:
            resp = requests.get(url, headers=self._get_headers(), timeout=15, verify=False, stream=True)
            resp.raise_for_status()
            content_length = resp.headers.get('Content-Length')
            if content_length and int(content_length) > 5 * 1024 * 1024:
                resp.close()
                self.on_log(f"  -> Skipped (file too large)")
                self.stats['files_skipped'] += 1
                return None
            text = resp.text
            resp.close()
            return text
        except:
            return None

    def _fetch_page(self, url):
        try:
            resp = requests.get(url, headers=self._get_headers(), timeout=15, verify=False)
            resp.raise_for_status()
            return resp
        except:
            return None

    def _get_headers(self):
        headers = dict(HEADERS)
        cookie = self.config.get('cookie')
        if cookie:
            headers['Cookie'] = cookie
        custom_headers = self.config.get('headers', {})
        headers.update(custom_headers)
        return headers

    def _log_summary(self):
        self.on_log(f"[+] Scan complete: {len(self.findings)} findings")
        self.on_log(f"    Files: {self.stats['files_scanned']} scanned, {self.stats['files_skipped']} skipped")
        self.on_log(f"    Regex: {self.stats['regex_hits']} hits | AI: {self.stats['ai_calls']} calls, {self.stats['ai_hits']} hits")
        if self.stats['duplicates_removed'] > 0:
            self.on_log(f"    Dedup: {self.stats['duplicates_removed']} duplicates removed")

    def get_stats(self):
        return dict(self.stats)