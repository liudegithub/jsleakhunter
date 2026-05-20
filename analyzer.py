"""
JSLeakHunter — AI Analyzer Module v3.2
NEVER skip JS files - analyze everything
Fixed: minified JS handling (proper segment extraction for AI)
Enhanced: Crypto key detection with short variable names
"""

import json
import re
import requests


SYSTEM_PROMPT = """You are a senior application security engineer specializing in frontend JavaScript security.
Your job is to analyze JavaScript source code for hardcoded secrets, credentials, and sensitive data leaks.

## CRITICAL INSTRUCTION
When in doubt, ALWAYS REPORT. False positives are acceptable, but missing a real secret is NOT acceptable.

## What to Look For - MUST REPORT

### HIGH Severity:
1. **client_secret** with ANY value
2. **API keys, tokens, passwords, secrets**
3. **AES/DES encryption keys** — CRITICAL: These are often assigned to SHORT variable names (single letters like r, n, t, o, a, c) and then used in crypto functions. Look for this pattern:
   - A string literal of exactly 16, 24, or 32 characters assigned to ANY variable
   - That variable is later used in `.enc.Utf8.parse()`, `.encrypt()`, `.decrypt()`, `CryptoJS`, `AES`, `DES`, `ECB`, `CBC`
   - Example: `var r="EEOMv762enZKsCry"` where `r` is later used in `AES.encrypt` or `.enc.Utf8.parse(r)`
   - The variable name does NOT need to contain "key" or "secret" — check the USAGE context
4. **Map service keys** (QQ Map, AMap, Google Maps)
5. **Cloud credentials** (AWS, Azure, GCP, Alibaba, Tencent)
6. **Database connection strings**
7. **Private keys, certificates**
8. **JWT tokens**

### What to IGNORE:
- Font data, CSS, UI code
- Library/framework internals
- Build artifacts

## Response Format
Return ONLY a JSON object:
{"findings": [{"line": <number>, "type": "<what>", "severity": "HIGH|MEDIUM|LOW", "evidence": "<full value>", "impact": "<what>", "recommendation": "<fix>"}]}

If no findings, return: {"findings": []}

## REMEMBER
When in doubt, REPORT IT. False positives are acceptable, missing real secrets is NOT acceptable.
"""


class AIAnalyzer:
    def __init__(self, api_url, api_key, model, on_log=None):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.model = model
        self.on_log = on_log or (lambda msg: None)
        self.session = requests.Session()
        self.total_tokens = 0

    def test_connection(self):
        try:
            resp = self.session.get(
                f"{self.api_url}/models",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=15
            )
            if resp.status_code == 200:
                models = [m['id'] for m in resp.json().get('data', [])]
                self.on_log(f"[+] API connected. Available models: {len(models)}")
                return True, models
            else:
                self.on_log(f"[!] API returned {resp.status_code}")
                return False, []
        except Exception as e:
            self.on_log(f"[!] API connection failed: {e}")
            return False, []

    def analyze(self, js_content, js_url, precheck_findings, full_scan=False):
        """Analyze a JS file for hardcoded leaks - NEVER skip JS files"""
        
        if not js_content or len(js_content.strip()) < 50:
            return []
        
        if full_scan:
            snippets = self._extract_full_content(js_content)
            self.on_log(f"  [*] Full scan: sending {len(snippets)} chars to AI")
        else:
            snippets = self._extract_snippets(js_content, precheck_findings)
        
        if not snippets:
            return []

        prompt = self._build_prompt(js_url, snippets, precheck_findings, len(js_content), full_scan)

        try:
            resp = self.session.post(
                f"{self.api_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.1,
                    "max_tokens": 4096
                },
                timeout=300 if full_scan else 120
            )
            resp.raise_for_status()
            result = resp.json()

            usage = result.get('usage', {})
            self.total_tokens += usage.get('total_tokens', 0)

            content = result['choices'][0]['message']['content']
            return self._parse_response(content, js_url)

        except requests.exceptions.Timeout:
            self.on_log("[!] AI request timed out")
            return []
        except Exception as e:
            error_msg = str(e)
            if len(error_msg) > 200:
                error_msg = error_msg[:200] + "..."
            self.on_log(f"[!] AI error: {error_msg}")
            return []

    def _extract_full_content(self, js_content):
        total_length = len(js_content)
        if total_length <= 15000:
            return js_content
        
        self.on_log(f"  [*] Large file ({total_length} chars), extracting key sections...")
        lines = js_content.split('\n')
        chunks = []
        chunk_size = 500
        overlap = 50
        
        for i in range(0, len(lines), chunk_size - overlap):
            end = min(i + chunk_size, len(lines))
            chunk = '\n'.join(lines[i:end])
            chunks.append(chunk)
            if len('\n'.join(chunks)) > 14000:
                break
        
        result = '\n'.join(chunks)
        if len(result) > 15000:
            result = result[:15000] + "\n... (truncated)"
        return result

    def _is_minified(self, js_content):
        """
        Detect if JS content is minified (few very long lines).
        Minified JS typically has 1-10 lines, each with thousands of characters.
        """
        lines = js_content.split('\n')
        non_empty = [l for l in lines if l.strip()]
        if len(non_empty) <= 10:
            max_len = max(len(l) for l in non_empty) if non_empty else 0
            if max_len > 1000:
                return True
        return False

    def _extract_snippets(self, js_content, findings):
        lines = js_content.split('\n')

        if not findings:
            if len(js_content) < 15000:
                return js_content[:14000]
            
            # Check if this is minified code (few very long lines)
            if self._is_minified(js_content):
                self.on_log(f"  [*] Detected minified code, extracting segments for AI...")
                return self._extract_minified_segments(js_content)
            
            return self._extract_config_sections(js_content)

        suspect_ranges = []
        for f in findings:
            center = f['line'] - 1
            start = max(0, center - 10)
            end = min(len(lines), center + 11)
            suspect_ranges.append((start, end))

        suspect_ranges.sort()
        merged = []
        for start, end in suspect_ranges:
            if merged and start <= merged[-1][1] + 5:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))

        snippets = []
        for start, end in merged:
            for i in range(start, min(end, len(lines))):
                snippets.append(f"L{i+1}: {lines[i].rstrip()[:300]}")
            snippets.append('---')

        result = '\n'.join(snippets)
        if len(result) > 15000:
            result = result[:15000] + "\n... (truncated)"
        return result

    def _extract_minified_segments(self, js_content):
        """
        Extract key segments from minified code.
        For minified JS (few lines, very long), we extract segments
        from beginning, middle, and end, plus keyword-matching regions.
        This ensures the AI can see enough of the code to find secrets.
        """
        total_len = len(js_content)
        segments = []
        seen_ranges = []
        
        def add_segment(start, end, label=""):
            """Add a segment, avoiding overlap with existing segments"""
            # Check for overlap
            for rs, re_ in seen_ranges:
                if start < re_ and end > rs:
                    # Merge or skip
                    return
            seg = js_content[start:end]
            if label:
                seg = f"[{label}] {seg}"
            segments.append(seg)
            seen_ranges.append((start, end))
        
        # Segment 1: Beginning (first 2000 chars)
        add_segment(0, min(2000, total_len), "file_start")
        
        # Segment 2: Middle
        if total_len > 4000:
            mid = total_len // 2
            add_segment(max(0, mid - 1000), min(total_len, mid + 1000), "file_middle")
        
        # Segment 3: End (last 2000 chars)
        if total_len > 4000:
            add_segment(max(0, total_len - 2000), total_len, "file_end")
        
        # Segment 4: Search for security-related keywords and extract context
        keywords = [
            'secret', 'Secret', 'SECRET',
            'key', 'Key', 'KEY',
            'token', 'Token', 'TOKEN',
            'password', 'Password', 'PASSWORD',
            'credential', 'Credential',
            'encrypt', 'Encrypt', 'decrypt', 'Decrypt',
            'apiKey', 'api_key', 'apikey', 'ApiKey',
            'access_key', 'accessKey', 'AccessKey',
            'client_secret', 'clientSecret', 'ClientSecret',
            'AES', 'DES', 'HMAC', 'RSA',
            'bearer', 'Bearer', 'jwt', 'JWT',
            'cookie', 'Cookie',
            'auth', 'Auth',
            'qqMapKey', 'mapKey', 'MapKey',
            'config', 'Config',
            'ECB', 'CBC', 'CTR', 'GCM',
            'Pkcs7', 'Pkcs5', 'ZeroPadding',
            'CryptoJS', 'crypto-js', 'Cipher',
            'enc.Utf8', 'enc.Hex', 'enc.Base64',
            'Blowfish', 'RC4',
            'private_key', 'privateKey', 'PrivateKey',
            'secret_key', 'secretKey', 'SecretKey',
            'encryption_key', 'encryptionKey', 'EncryptionKey',
            'signing_key', 'signingKey', 'SigningKey',
            'hmac_key', 'hmacKey', 'HmacKey',
            'master_key', 'masterKey', 'MasterKey',
            'app_secret', 'appSecret', 'AppSecret',
            'consumer_secret', 'consumerSecret',
            'access_token', 'accessToken', 'AccessToken',
            'refresh_token', 'refreshToken', 'RefreshToken',
            'session_token', 'sessionToken',
            'Authorization', 'Bearer',
            'connection_string', 'connectionString',
            'database_url', 'databaseUrl',
            'redis_url', 'redisUrl',
            'mysql', 'postgres', 'mongodb',
            'aws_secret', 'aws_access',
            'firebase', 'Firebase',
            'stripe', 'Stripe',
            'github', 'GitHub',
        ]
        
        content_lower = js_content.lower()
        keyword_positions = []
        
        for kw in keywords:
            kw_lower = kw.lower()
            pos = 0
            while True:
                idx = content_lower.find(kw_lower, pos)
                if idx == -1:
                    break
                keyword_positions.append((idx, kw))
                pos = idx + len(kw_lower)
        
        # Sort by position
        keyword_positions.sort(key=lambda x: x[0])
        
        # Extract segments around each keyword
        for pos, kw in keyword_positions:
            seg_start = max(0, pos - 150)
            seg_end = min(total_len, pos + 400)
            add_segment(seg_start, seg_end, f"keyword:{kw}")
            
            # Stop if we have enough content
            total_extracted = sum(len(s) for s in segments)
            if total_extracted > 12000:
                break
        
        result = '\n---\n'.join(segments)
        if len(result) > 15000:
            result = result[:15000] + "\n... (truncated)"
        return result

    def _extract_config_sections(self, js_content):
        lines = js_content.split('\n')
        config_lines = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            
            # For very long lines (minified code), search for keywords within segments
            if len(stripped) > 1000:
                for kw in ['config', 'settings', 'env', 'secret',
                           'api_key', 'apikey', 'token', 'password', 'credential',
                           'client_id', 'client_secret', 'encrypt', 'decrypt',
                           'mapkey', 'mapKey', 'qqMapKey']:
                    kw_lower = kw.lower()
                    content_lower = stripped.lower()
                    idx = 0
                    while True:
                        pos = content_lower.find(kw_lower, idx)
                        if pos == -1:
                            break
                        seg_start = max(0, pos - 200)
                        seg_end = min(len(stripped), pos + 500)
                        config_lines.append('---')
                        config_lines.append(f"L{i+1}[{pos}]: {stripped[seg_start:seg_end]}")
                        idx = pos + len(kw_lower)
                        if len('\n'.join(config_lines)) > 10000:
                            break
                    if len('\n'.join(config_lines)) > 10000:
                        break
            else:
                if any(kw in stripped.lower() for kw in [
                    'config', 'settings', 'env', 'secret',
                    'api_key', 'apikey', 'token', 'password', 'credential',
                    'client_id', 'client_secret', 'encrypt', 'decrypt',
                    'mapkey', 'mapKey', 'qqMapKey',
                ]):
                    start = max(0, i - 2)
                    end = min(len(lines), i + 10)
                    config_lines.append('---')
                    for j in range(start, end):
                        config_lines.append(f"L{j+1}: {lines[j].rstrip()[:300]}")

        if not config_lines:
            return None

        result = '\n'.join(config_lines)
        if len(result) > 12000:
            result = result[:12000]
        return result

    def _build_prompt(self, js_url, code_snippets, precheck_findings, file_size, full_scan=False):
        findings_lines = []
        for f in precheck_findings[:15]:
            evidence = f.get('evidence', '')[:100]
            findings_lines.append(f"  L{f['line']}: [{f.get('type','Unknown')}] {evidence}")
        findings_text = '\n'.join(findings_lines) if findings_lines else '  (none)'

        scan_mode = "FULL FILE SCAN" if full_scan else "TARGETED SCAN"
        
        full_scan_hint = ""
        if full_scan:
            full_scan_hint = """
## IMPORTANT: This is a FULL FILE SCAN
- The code below is the ENTIRE JavaScript file (or large portions of it)
- Look VERY CAREFULLY for any secrets
- Pay special attention to:
  - client_secret, client_id values
  - API keys, tokens, passwords
  - Encryption keys (AES, DES) — even if assigned to short variable names like r, n, t
  - Database credentials
  - Map service keys (QQ Map, AMap, Google Maps)
  - Any hardcoded configuration values that look sensitive
"""

        prompt = "Analyze this JavaScript file for hardcoded secrets.\n\n"
        prompt += "## Scan Mode\n"
        prompt += scan_mode + "\n"
        prompt += full_scan_hint + "\n"
        prompt += "## File Info\n"
        prompt += "- URL: " + js_url + "\n"
        prompt += "- Size: " + str(file_size) + " bytes\n\n"
        prompt += "## Regex Pre-scan Results\n"
        prompt += findings_text + "\n\n"
        prompt += "## Code\n"
        prompt += code_snippets + "\n\n"
        prompt += """## Task
Find ALL hardcoded secrets in this code. Pay special attention to:

1. **client_secret** - This is ALWAYS a secret, even if short
2. **client_id** - Often paired with client_secret
3. **API keys** - Any string that looks like an API key
4. **Passwords** - Any password value
5. **Tokens** - Any authentication token
6. **Encryption keys** - Any key used for encryption (AES, DES, etc.)
7. **Map service keys** - QQ Map, AMap, Baidu Map, Google Maps keys

## CRITICAL RULES
- If you see `client_secret:"anything"`, REPORT IT as HIGH severity
- If you see `password:"anything"`, REPORT IT as HIGH severity
- If you see `apiKey:"anything"`, REPORT IT as HIGH severity
- If you see a key used with `encrypt`/`decrypt`, REPORT IT as HIGH severity
- Show the FULL secret value in evidence, do NOT mask it

## CRYPTO KEY DETECTION (VERY IMPORTANT)
Hardcoded encryption keys are often hidden like this:
var r="EEOMv762enZKsCry";   // 16-char AES key, variable name is just "r"
// ... much later in the code ...
o.default.enc.Utf8.parse(r)  // used as AES key
o.default.AES.encrypt(data, key, {mode:ECB, padding:Pkcs7})
To find these:
1. Scan for string literals that are EXACTLY 16, 24, or 32 alphanumeric characters
2. Check if that variable name appears near `.encrypt`, `.decrypt`, `.enc.`, `AES`, `DES`, `CryptoJS`, `ECB`, `CBC`, `Utf8.parse`
3. If YES → REPORT IT as "AES/DES Encryption Key" with HIGH severity
4. The variable name can be ANYTHING (r, n, t, key, secret, a, b, x, etc.)

## Response Format
Return ONLY a JSON object:
{
  "findings": [
    {
      "line": <line_number>,
      "type": "<what was found>",
      "severity": "HIGH|MEDIUM|LOW",
      "evidence": "<the actual secret value>",
      "impact": "<what an attacker could do>",
      "recommendation": "<how to fix>"
    }
  ]
}

If no findings, return: {"findings": []}

## REMEMBER
When in doubt, REPORT IT. False positives are acceptable, missing real secrets is NOT acceptable.
"""
        return prompt

    def _parse_response(self, content, js_url):
        content = re.sub(r'```(?:json)?\s*', '', content)
        content = re.sub(r'```\s*$', '', content.strip())
        
        json_match = re.search(r'\{[\s\S]*\}', content)
        if json_match:
            content = json_match.group()
        
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            findings_match = re.search(r'"findings"\s*:\s*\[([\s\S]*?)\]', content)
            if findings_match:
                try:
                    findings_str = findings_match.group(1)
                    content_fixed = '{"findings": [' + findings_str + ']}'
                    data = json.loads(content_fixed)
                except json.JSONDecodeError:
                    self.on_log(f"[!] AI response parse error: {str(e)[:100]}")
                    return []
            else:
                self.on_log(f"[!] AI response missing 'findings' key")
                return []

        findings = data.get('findings', [])
        if not isinstance(findings, list):
            self.on_log("[!] Invalid findings format")
            return []

        filtered = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            if not f.get('line') or not f.get('type'):
                continue

            f['url'] = js_url
            f['source'] = 'ai'
            f.setdefault('severity', 'MEDIUM')
            f.setdefault('evidence', '')
            f.setdefault('impact', '')
            f.setdefault('recommendation', 'Manual review required')
            
            try:
                f['line'] = int(f['line'])
            except (ValueError, TypeError):
                f['line'] = 0
                
            filtered.append(f)

        return filtered

    def get_usage(self):
        return {"total_tokens": self.total_tokens}