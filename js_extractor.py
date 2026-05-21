"""
JSLeakHunter — Enhanced JavaScript Extractor v2.1
Comprehensive JS file discovery including dynamic loading
Enhanced: Webpack runtime analysis and chunk URL generation
Enhanced: Playwright real-time network monitoring (like 雪瞳)
Enhanced: Dual URL generation strategy (filename + chunkId fallback)
"""

import re
import json
import urllib.parse
from typing import Set, List, Dict, Tuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup


@dataclass
class ExtractedJS:
    """Represents an extracted JavaScript resource"""
    url: str
    source_type: str
    parent_url: str
    content: Optional[str] = None
    line_number: Optional[int] = None


class DynamicJSExtractor:
    """Enhanced JS file extractor that captures dynamically loaded scripts"""
    
    DYNAMIC_LOAD_PATTERNS = [
        (r'''document\.createElement\s*\(\s*['"]script['"]\s*\)''', 'createElement'),
        (r'''\.src\s*=\s*['"]([^'"]+\.js[^'"]*)['"]''', 'src_assignment'),
        (r'''\.setAttribute\s*\(\s*['"]src['"]\s*,\s*['"]([^'"]+\.js[^'"]*)['"]''', 'setAttribute'),
        (r'''import\s*\(\s*['"]([^'"]+)['"]\s*\)''', 'dynamic_import'),
        (r'''new\s+Worker\s*\(\s*['"]([^'"]+)['"]''', 'worker'),
        (r'''navigator\.serviceWorker\.register\s*\(\s*['"]([^'"]+)['"]''', 'service_worker'),
    ]
    
    def __init__(self, base_url: str, headers: dict, timeout: int = 15, verify_ssl: bool = False, on_log=None):
        self.base_url = base_url
        self.headers = headers
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.visited_urls: Set[str] = set()
        self.extracted_js: List[ExtractedJS] = []
        self.session = requests.Session()
        self.session.headers.update(headers)
        self.webpack_public_path: Optional[str] = None
        self.webpack_hash_pattern: Optional[str] = None
        # Webpack runtime info
        self.webpack_chunk_maps: Optional[List[Dict]] = None
        self.webpack_url_template: Optional[str] = None
        self.webpack_url_template_parts: Optional[List[str]] = None
        self.webpack_url_prefix: Optional[str] = None
        self.webpack_url_suffix: Optional[str] = None
        self.webpack_chunk_global: Optional[str] = None
        self.webpack_entry_analyzed: Set[str] = set()
        # Separated filename and hash maps for better URL generation
        self.webpack_filename_map: Optional[Dict] = None
        self.webpack_hash_map: Optional[Dict] = None
        self.on_log = on_log or (lambda msg: None)
    
    def extract_all_js(self, html_content: str, page_url: str, depth: int = 2) -> List[ExtractedJS]:
        """Main entry point: Extract all JS files from a page and its resources"""
        self.extracted_js = []
        self.visited_urls = set()
        self.webpack_public_path = None
        self.webpack_hash_pattern = None
        self.webpack_chunk_maps = None
        self.webpack_url_template = None
        self.webpack_url_template_parts = None
        self.webpack_url_prefix = None
        self.webpack_url_suffix = None
        self.webpack_chunk_global = None
        self.webpack_entry_analyzed = set()
        # Reset separated maps
        self.webpack_filename_map = None
        self.webpack_hash_map = None
        
        # Phase 1: Extract from HTML
        self._extract_from_html(html_content, page_url)
        
        # Phase 2: Analyze inline scripts for dynamic loading
        self._analyze_inline_scripts(html_content, page_url)
        
        # Phase 3: Download and analyze external JS files
        if depth > 0:
            self._analyze_external_js(depth)
        
        # Phase 3.5: Analyze webpack entry bundles for runtime info
        self._analyze_webpack_entry_bundles(page_url)
        
        # Phase 4: Generate Webpack chunk URLs
        self._generate_webpack_chunks(page_url)
        self._generate_webpack_chunks_enhanced(page_url)
        
        return self._deduplicate()
    
    def _extract_from_html(self, html_content: str, page_url: str):
        """Extract JS references from HTML markup"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for tag in soup.find_all('script', src=True):
            url = self._resolve_url(page_url, tag['src'])
            if url and self._is_js_url(url):
                self._add_js(url, 'script_tag', page_url)
        
        for tag in soup.find_all('link', attrs={'as': 'script', 'href': True}):
            url = self._resolve_url(page_url, tag['href'])
            if url:
                self._add_js(url, 'preload', page_url)
        
        for tag in soup.find_all('link', attrs={'rel': 'modulepreload', 'href': True}):
            url = self._resolve_url(page_url, tag['href'])
            if url:
                self._add_js(url, 'modulepreload', page_url)
    
    def _analyze_inline_scripts(self, html_content: str, page_url: str):
        """Analyze inline scripts for dynamic loading patterns"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for idx, tag in enumerate(soup.find_all('script', src=False)):
            code = tag.string or tag.get_text()
            if not code or len(code.strip()) < 20:
                continue
            
            self._extract_dynamic_urls(code, page_url, f'inline_script_{idx}')
            self._extract_webpack_config(code, page_url)
            self._extract_webpack_runtime_info(code, page_url)
    
    def _extract_dynamic_urls(self, code: str, base_url: str, source: str):
        """Extract URLs from dynamic loading patterns"""
        for pattern, pattern_type in self.DYNAMIC_LOAD_PATTERNS:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                url = match.group(1) if match.lastindex else match.group(0)
                url = self._clean_dynamic_url(url, code, match.start())
                
                if url and url.endswith('.js'):
                    resolved = self._resolve_url(base_url, url)
                    if resolved:
                        self._add_js(resolved, f'dynamic_{pattern_type}', base_url)
    
    def _extract_webpack_config(self, code: str, base_url: str):
        """Extract Webpack configuration from runtime code"""
        public_path_match = re.search(r'''__webpack_require__\.p\s*=\s*["']([^"']+)["']''', code)
        if public_path_match:
            self.webpack_public_path = public_path_match.group(1)
            if self.webpack_public_path.startswith('./') or self.webpack_public_path.startswith('/'):
                self.webpack_public_path = self._resolve_url(base_url, self.webpack_public_path)
        
        hash_match = re.search(r'''\+\s*["']\.(\d{10,13}\.js)["']''', code)
        if hash_match:
            self.webpack_hash_pattern = hash_match.group(1)
    
    def _analyze_webpack_entry_bundles(self, page_url: str):
        """Analyze webpack entry bundles for runtime info"""
        for js in list(self.extracted_js):
            if js.content is None:
                continue
            
            url_key = js.url.split('?')[0]
            if url_key in self.webpack_entry_analyzed:
                continue
            self.webpack_entry_analyzed.add(url_key)
            
            content = js.content
            
            is_webpack = (
                '__webpack_require__' in content or
                'webpackJsonp' in content or
                'webpackChunk' in content
            )
            
            if not is_webpack:
                continue
            
            if '__webpack_require__.p' in content or 'jsonpScriptSrc' in content or '.u=' in content:
                self._extract_webpack_runtime_info(content, page_url)
    
    def _extract_webpack_runtime_info(self, content: str, base_url: str):
        """
        Extract webpack runtime info from entry bundle.
        General approach: parse real URL template from code, no hardcoded extensions.
        """
        # 1. Extract publicPath
        public_path_match = re.search(
            r'__webpack_require__\.p\s*=\s*["\']([^"\']+)["\']',
            content
        )
        if public_path_match:
            self.webpack_public_path = public_path_match.group(1)
            if self.webpack_public_path.startswith(('./', '/')):
                self.webpack_public_path = self._resolve_url(base_url, self.webpack_public_path)
            elif not self.webpack_public_path.startswith('http'):
                self.webpack_public_path = self._resolve_url(base_url, self.webpack_public_path)

        # 2. Find chunk URL function
        u_func_body = self._find_chunk_url_function(content)
        
        if u_func_body:
            self._parse_webpack_chunk_map(u_func_body, base_url)
            self._extract_url_template_from_return(u_func_body)

        # 3. Extract webpackChunk global variable name
        chunk_global_match = re.search(
            r'self\[["\'](\w+)["\']\s*=\s*self\[["\']\1["\']\s*\|\|\s*\[\]',
            content
        )
        if chunk_global_match:
            self.webpack_chunk_global = chunk_global_match.group(1)

        # 4. Fallback: extract chunk maps from entire content
        if not self.webpack_chunk_maps:
            self._extract_chunk_maps_generic(content, base_url)
        
        # 5. NEW: Direct suffix detection from webpack runtime code
        # This is a fallback when _find_chunk_url_function fails to parse compressed code
        if self.webpack_url_suffix == '.js' or self.webpack_url_suffix is None:
            # Look for common webpack URL suffix patterns in the content
            # Pattern: + ".async.js" or + ".chunk.js" near .u= or chunk loading
            suffix_patterns = [
                r'\+["\']\.async\.js["\']',      # + ".async.js"
                r'\+["\']\.chunk\.js["\']',       # + ".chunk.js"
                r'\.async\.js["\']',               # .async.js"
                r'\.chunk\.js["\']',               # .chunk.js"
            ]
            
            for sp in suffix_patterns:
                match = re.search(sp, content)
                if match:
                    # Extract the actual suffix
                    suffix_match = re.search(r'(\.\w+\.js)', match.group(0))
                    if suffix_match:
                        self.webpack_url_suffix = suffix_match.group(1)
                        self.on_log(f"  [*] Direct suffix detection: found '{self.webpack_url_suffix}'")
                        break
            
            # If still no suffix found, check for .u= function and try to extract suffix
            if self.webpack_url_suffix == '.js' or self.webpack_url_suffix is None:
                # Look for pattern: }[h]+".async.js" or }[n]+".async.js"
                u_suffix_match = re.search(r'\}\s*\[\s*[a-zA-Z_$]+\s*\]\s*\+\s*["\'](\.\w+\.js)["\']', content)
                if u_suffix_match:
                    self.webpack_url_suffix = u_suffix_match.group(1)
                    self.on_log(f"  [*] U-function suffix detection: found '{self.webpack_url_suffix}'")
    
    def _find_chunk_url_function(self, content: str) -> Optional[str]:
        """
        Find chunk URL generation function body.
        Supports: __webpack_require__.u, jsonpScriptSrc, compressed variants.
        """
        patterns = [
            r'__webpack_require__\.u\s*=\s*function\s*\([^)]*\)\s*\{(.*?)\n\s*\}',
            r'function\s+jsonpScriptSrc\s*\([^)]*\)\s*\{(.*?)\n\s*\}',
            r'[a-zA-Z_$]+\.u\s*=\s*function\s*\([a-zA-Z_$]*\)\s*\{(.*?)\n\s*\}',
            r'[a-zA-Z_$]+\.u\s*=\s*function\s*\([a-zA-Z_$]*\)\s*\{return\s+[^}]+\}',
            r'__webpack_require__\.u\s*=\s*function\s+[a-zA-Z_$]+\s*\([a-zA-Z_$]*\)\s*\{(.*?)\n\s*\}',
            # Match compressed/uglified patterns like: t.u = function(h) { return "" + ({...}[h] || h) + "." + {...}[h] + ".async.js" }
            r'[a-zA-Z_$]+\.u\s*=\s*function\s*\([a-zA-Z_$]+\)\s*\{return\s+""\+\(.*?\)\}',
        ]
        
        for i, pattern in enumerate(patterns):
            match = re.search(pattern, content, re.DOTALL)
            if match:
                self.on_log(f"  [DEBUG] Found chunk URL function with pattern {i}")
                return match.group(0)
        
        # 调试：检查是否有 .u = function 模式
        if '.u=' in content or '.u =' in content:
            self.on_log(f"  [DEBUG] Content contains '.u=' but no pattern matched")
            # 尝试提取一小段看看
            idx = content.find('.u=')
            if idx == -1:
                idx = content.find('.u =')
            if idx != -1:
                snippet = content[idx:idx+200]
                self.on_log(f"  [DEBUG] Snippet around .u=: {snippet[:100]}")
        
        return None
    
    def _extract_url_template_from_return(self, func_body: str):
        """
        Extract URL template from return statement.
        General approach: parse string concatenation to get prefix/suffix.
        Enhanced: Correctly extract .async.js suffix from webpack runtime.
        """
        return_match = re.search(r'return\s+([^;]+)', func_body)
        if not return_match:
            return
        
        return_expr = return_match.group(1)
        
        # Extract all string literals
        string_parts = re.findall(r'["\']([^"\']*)["\']', return_expr)
        
        if string_parts:
            self.webpack_url_template_parts = string_parts
            
            # Filter out empty strings to find the actual suffix
            # Example: "" + ({...}[h] || h) + "." + {...}[h] + ".async.js"
            # String parts: ['', '.', '.async.js']
            # We want: prefix='', suffix='.async.js'
            non_empty_parts = [s for s in string_parts if s]
            
            if non_empty_parts:
                # The last non-empty string is typically the suffix
                # (.async.js, .chunk.js, .js, etc.)
                self.webpack_url_suffix = non_empty_parts[-1]
                # The first non-empty string (if different from suffix) is the prefix
                if len(non_empty_parts) > 1:
                    self.webpack_url_prefix = non_empty_parts[0] if non_empty_parts[0] != non_empty_parts[-1] else ''
                else:
                    self.webpack_url_prefix = ''
            else:
                # All strings are empty, default to .js
                self.webpack_url_suffix = '.js'
                self.webpack_url_prefix = ''
            
            self.on_log(f"  [*] Extracted URL template: prefix='{self.webpack_url_prefix}', suffix='{self.webpack_url_suffix}'")
    
    def _parse_webpack_chunk_map(self, func_body: str, base_url: str):
        """
        Parse webpack chunk loading function for chunk ID -> filename/hash mapping.
        Enhanced: Better separation of filename map and hash map.
        """
        # Find all {...}[variable] patterns in the function body
        obj_pattern = re.compile(
            r"""\{([^{}]+)\}\s*\[(?:[a-zA-Z_$]+(?:\s*(?:\|\||\?)\s*[a-zA-Z_$"']*)?)\]"""
        )
        
        chunk_maps = []
        for match in obj_pattern.finditer(func_body):
            obj_content = match.group(1)
            pairs = re.findall(r'["\']?(\w+)["\']?\s*:\s*["\']([^"\']+)["\']', obj_content)
            if pairs:
                chunk_maps.append(dict(pairs))
        
        if chunk_maps:
            self.webpack_chunk_maps = chunk_maps
            
            # Enhanced: Separate filename map and hash map
            # filename map values typically contain _ or - or are long names
            # hash map values are typically short hex strings
            if len(chunk_maps) >= 2:
                map1_values = list(chunk_maps[0].values())[:15]
                map2_values = list(chunk_maps[1].values())[:15]
                
                # Check which map has filenames (containing _ or - or long names)
                map1_has_names = any('_' in v or '-' in v or len(v) > 15 for v in map1_values)
                map2_has_names = any('_' in v or '-' in v or len(v) > 15 for v in map2_values)
                
                if map1_has_names and not map2_has_names:
                    # Standard order: map1 = filenames, map2 = hashes
                    self.webpack_filename_map = chunk_maps[0]
                    self.webpack_hash_map = chunk_maps[1]
                elif map2_has_names and not map1_has_names:
                    # Reversed order: map1 = hashes, map2 = filenames
                    self.webpack_filename_map = chunk_maps[1]
                    self.webpack_hash_map = chunk_maps[0]
                else:
                    # Can't determine, assume standard order
                    self.webpack_filename_map = chunk_maps[0]
                    self.webpack_hash_map = chunk_maps[1]
            elif len(chunk_maps) == 1:
                # Only one map, check if it's filename or hash
                values = list(chunk_maps[0].values())[:15]
                has_names = any('_' in v or '-' in v or len(v) > 15 for v in values)
                if has_names:
                    self.webpack_filename_map = chunk_maps[0]
                    self.webpack_hash_map = {}
                else:
                    self.webpack_filename_map = {}
                    self.webpack_hash_map = chunk_maps[0]
    
    def _generate_webpack_chunks_enhanced(self, page_url: str):
        """
        Enhanced webpack chunk generation.
        General approach: detect URL pattern from existing URLs, no hardcoded extensions.
        """
        if not self.webpack_chunk_maps:
            return
        
        public_path = self.webpack_public_path
        if not public_path:
            for js in self.extracted_js:
                if re.search(r'\.\w{6,20}\.(?:async|chunk)?\.?js', js.url):
                    parsed = urllib.parse.urlparse(js.url)
                    path_parts = parsed.path.rsplit('/', 1)
                    if len(path_parts) > 1:
                        public_path = f"{parsed.scheme}://{parsed.netloc}{path_parts[0]}/"
                        break
            if not public_path:
                for js in self.extracted_js:
                    if js.source_type == 'script_tag':
                        parsed = urllib.parse.urlparse(js.url)
                        path_parts = parsed.path.rsplit('/', 1)
                        if len(path_parts) > 1:
                            public_path = f"{parsed.scheme}://{parsed.netloc}{path_parts[0]}/"
                            break
        
        if not public_path:
            self.on_log("  [-] No public path found for webpack chunks")
            return
        
        chunk_maps = self.webpack_chunk_maps
        
        # Detect URL pattern from existing URLs
        url_pattern_info = self._detect_url_pattern_from_existing()
        
        if url_pattern_info:
            self._generate_urls_from_pattern(chunk_maps, public_path, url_pattern_info, page_url)
        else:
            # Fallback: try to detect suffix from existing URLs
            detected_suffix = None
            for js in self.extracted_js:
                filename = js.url.split('/')[-1].split('?')[0]
                if '.async.js' in filename:
                    detected_suffix = '.async.js'
                    break
                if '.chunk.js' in filename:
                    detected_suffix = '.chunk.js'
                    break
            
            # Use detected suffix or webpack_url_suffix
            suffix = detected_suffix or self.webpack_url_suffix or '.js'
            
            # If we have a non-default suffix, generate URLs directly
            if suffix and suffix != '.js':
                self.on_log(f"  [*] Using suffix '{suffix}' for URL generation")
                self._generate_urls_with_suffix(chunk_maps, public_path, suffix, page_url)
            else:
                self._generate_urls_generic(chunk_maps, public_path, page_url)
    
    def _generate_urls_with_suffix(self, chunk_maps, public_path, suffix, page_url):
        """
        Generate URLs with a specific suffix.
        Used when pattern detection fails but we know the suffix.
        """
        generated = 0
        
        # Use separated maps if available
        filename_map = self.webpack_filename_map or {}
        hash_map = self.webpack_hash_map or {}
        
        # If separated maps are not available, try to determine from chunk_maps
        if not filename_map and not hash_map:
            if len(chunk_maps) >= 2:
                map1_values = list(chunk_maps[0].values())[:10]
                map2_values = list(chunk_maps[1].values())[:10]
                map1_has_names = any('_' in v or '-' in v or len(v) > 15 for v in map1_values)
                map2_has_names = any('_' in v or '-' in v or len(v) > 15 for v in map2_values)
                
                if map1_has_names and not map2_has_names:
                    filename_map = chunk_maps[0]
                    hash_map = chunk_maps[1]
                elif map2_has_names and not map1_has_names:
                    filename_map = chunk_maps[1]
                    hash_map = chunk_maps[0]
                else:
                    filename_map = chunk_maps[0]
                    hash_map = chunk_maps[1]
            elif len(chunk_maps) == 1:
                values = list(chunk_maps[0].values())[:10]
                has_names = any('_' in v or '-' in v or len(v) > 15 for v in values)
                if has_names:
                    filename_map = chunk_maps[0]
                else:
                    hash_map = chunk_maps[0]
        
        # Get all unique chunk IDs
        all_chunk_ids = set()
        if filename_map:
            all_chunk_ids.update(filename_map.keys())
        if hash_map:
            all_chunk_ids.update(hash_map.keys())
        
        if not all_chunk_ids:
            return
        
        self.on_log(f"  [*] Generating URLs with suffix '{suffix}' for {len(all_chunk_ids)} chunks")
        
        for chunk_id in all_chunk_ids:
            filename = filename_map.get(chunk_id, '')
            hash_val = hash_map.get(chunk_id, '')
            
            # Format 1: Use filename if available (e.g., p__module__index.hash.async.js)
            if filename and hash_val:
                url = f"{public_path.rstrip('/')}/{filename}.{hash_val}{suffix}"
                if self._add_js(url, 'webpack_chunk_enhanced', page_url):
                    generated += 1
            
            # Format 2: Use chunkId as filename (e.g., 4726.hash.async.js)
            # This is the key strategy from 雪瞳
            if hash_val:
                url = f"{public_path.rstrip('/')}/{chunk_id}.{hash_val}{suffix}"
                if self._add_js(url, 'webpack_chunk_enhanced', page_url):
                    generated += 1
            
            # Format 3: Only filename without hash (rare case)
            if filename and not hash_val:
                url = f"{public_path.rstrip('/')}/{filename}{suffix}"
                if self._add_js(url, 'webpack_chunk_enhanced', page_url):
                    generated += 1
        
        if generated > 0:
            self.on_log(f"  [+] Generated {generated} webpack chunk URLs with suffix '{suffix}'")
    
    def _detect_url_pattern_from_existing(self) -> Optional[Dict]:
        """
        Detect filename pattern from existing JS URLs.
        General approach: analyze URL structure, extract template.
        Supports: .js, .async.js, .chunk.js, etc.
        """
        chunk_urls = []
        for js in self.extracted_js:
            url = js.url
            filename = url.split('/')[-1].split('?')[0].lower()
            if any(name in filename for name in ['main', 'app.js', 'vendor', 'umi', 'polyfill', 'runtime', 'preload']):
                continue
            if 'font' in filename:
                continue
            chunk_urls.append(url)
        
        if not chunk_urls:
            return None
        
        patterns_found = {}
        
        for url in chunk_urls:
            filename = url.split('/')[-1].split('?')[0]
            
            m = re.match(r'^(\d+)\.([a-f0-9]{6,20})\.async\.js$', filename)
            if m:
                patterns_found['number_hash_async_js'] = patterns_found.get('number_hash_async_js', 0) + 1
                continue
            
            m = re.match(r'^([a-zA-Z0-9_\-.]+)\.([a-f0-9]{6,20})\.async\.js$', filename)
            if m:
                patterns_found['name_hash_async_js'] = patterns_found.get('name_hash_async_js', 0) + 1
                continue
            
            m = re.match(r'^([a-zA-Z0-9_\-.]+)\.([a-f0-9]{6,20})\.js$', filename)
            if m:
                patterns_found['name_hash_js'] = patterns_found.get('name_hash_js', 0) + 1
                continue
            
            m = re.match(r'^([a-zA-Z0-9_\-.]+)\.([a-f0-9]{6,20})\.chunk\.js$', filename)
            if m:
                patterns_found['name_hash_chunk_js'] = patterns_found.get('name_hash_chunk_js', 0) + 1
                continue
            
            m = re.match(r'^(\d+)\.([a-f0-9]{6,20})\.js$', filename)
            if m:
                patterns_found['number_hash_js'] = patterns_found.get('number_hash_js', 0) + 1
                continue
        
        if not patterns_found:
            return None
        
        best_pattern = max(patterns_found, key=patterns_found.get)
        
        for url in chunk_urls:
            filename = url.split('/')[-1].split('?')[0]
            
            if best_pattern == 'number_hash_async_js':
                m = re.match(r'^\d+\.([a-f0-9]{6,20})\.async\.js$', filename)
                if m:
                    return {'type': 'number_hash_async_js', 'hash': m.group(1), 'suffix': '.async.js', 'template': '{id}.{hash}.async.js'}
            
            elif best_pattern == 'name_hash_async_js':
                m = re.match(r'^([a-zA-Z0-9_\-.]+)\.([a-f0-9]{6,20})\.async\.js$', filename)
                if m:
                    return {'type': 'name_hash_async_js', 'name': m.group(1), 'hash': m.group(2), 'suffix': '.async.js', 'template': '{name}.{hash}.async.js'}
            
            elif best_pattern == 'name_hash_js':
                m = re.match(r'^([a-zA-Z0-9_\-.]+)\.([a-f0-9]{6,20})\.js$', filename)
                if m:
                    return {'type': 'name_hash_js', 'name': m.group(1), 'hash': m.group(2), 'suffix': '.js', 'template': '{name}.{hash}.js'}
            
            elif best_pattern == 'name_hash_chunk_js':
                m = re.match(r'^([a-zA-Z0-9_\-.]+)\.([a-f0-9]{6,20})\.chunk\.js$', filename)
                if m:
                    return {'type': 'name_hash_chunk_js', 'name': m.group(1), 'hash': m.group(2), 'suffix': '.chunk.js', 'template': '{name}.{hash}.chunk.js'}
            
            elif best_pattern == 'number_hash_js':
                m = re.match(r'^(\d+)\.([a-f0-9]{6,20})\.js$', filename)
                if m:
                    return {'type': 'number_hash_js', 'hash': m.group(2), 'suffix': '.js', 'template': '{id}.{hash}.js'}
        
        return None
    
    def _generate_urls_from_pattern(self, chunk_maps, public_path, pattern_info, page_url):
        """
        Generate URLs using detected pattern.
        Enhanced: Generate BOTH filename-based and chunkId-based URLs (雪瞳 strategy).
        """
        generated = 0
        suffix = pattern_info.get('suffix', '.js')
        
        # Use separated maps if available, otherwise fall back to chunk_maps
        filename_map = self.webpack_filename_map or {}
        hash_map = self.webpack_hash_map or {}
        
        # If separated maps are not available, try to determine from chunk_maps
        if not filename_map and not hash_map:
            if len(chunk_maps) >= 2:
                # Heuristic: check which map has filenames
                map1_values = list(chunk_maps[0].values())[:10]
                map2_values = list(chunk_maps[1].values())[:10]
                map1_has_names = any('_' in v or '-' in v or len(v) > 15 for v in map1_values)
                map2_has_names = any('_' in v or '-' in v or len(v) > 15 for v in map2_values)
                
                if map1_has_names and not map2_has_names:
                    filename_map = chunk_maps[0]
                    hash_map = chunk_maps[1]
                elif map2_has_names and not map1_has_names:
                    filename_map = chunk_maps[1]
                    hash_map = chunk_maps[0]
                else:
                    filename_map = chunk_maps[0]
                    hash_map = chunk_maps[1]
            elif len(chunk_maps) == 1:
                values = list(chunk_maps[0].values())[:10]
                has_names = any('_' in v or '-' in v or len(v) > 15 for v in values)
                if has_names:
                    filename_map = chunk_maps[0]
                else:
                    hash_map = chunk_maps[0]
        
        # Get all unique chunk IDs
        all_chunk_ids = set()
        if filename_map:
            all_chunk_ids.update(filename_map.keys())
        if hash_map:
            all_chunk_ids.update(hash_map.keys())
        
        if not all_chunk_ids:
            return
        
        for chunk_id in all_chunk_ids:
            filename = filename_map.get(chunk_id, '')
            hash_val = hash_map.get(chunk_id, '')
            
            # Format 1: Use filename if available (e.g., p__module__index.hash.async.js)
            if filename and hash_val:
                url = f"{public_path.rstrip('/')}/{filename}.{hash_val}{suffix}"
                if self._add_js(url, 'webpack_chunk_enhanced', page_url):
                    generated += 1
            
            # Format 2: Use chunkId as filename (e.g., 4726.hash.async.js)
            # This is the key strategy from 雪瞳 - always generate this format as fallback
            if hash_val:
                url = f"{public_path.rstrip('/')}/{chunk_id}.{hash_val}{suffix}"
                if self._add_js(url, 'webpack_chunk_enhanced', page_url):
                    generated += 1
            
            # Format 3: Only filename without hash (rare case)
            if filename and not hash_val:
                url = f"{public_path.rstrip('/')}/{filename}{suffix}"
                if self._add_js(url, 'webpack_chunk_enhanced', page_url):
                    generated += 1
        
        if generated > 0:
            self.on_log(f"  [+] Generated {generated} webpack chunk URLs (enhanced)")
    
    def _generate_urls_generic(self, chunk_maps, public_path, page_url):
        """
        Generic fallback: simple URL generation with auto-detected suffix.
        Enhanced: Generate BOTH filename-based and chunkId-based URLs.
        """
        generated = 0
        
        # Auto-detect suffix from existing URLs
        suffix = '.js'
        for js in self.extracted_js:
            filename = js.url.split('/')[-1].split('?')[0]
            if '.async.js' in filename:
                suffix = '.async.js'
                break
            if '.chunk.js' in filename:
                suffix = '.chunk.js'
                break
        
        # Use separated maps if available
        filename_map = self.webpack_filename_map or {}
        hash_map = self.webpack_hash_map or {}
        
        # If separated maps are not available, try to determine from chunk_maps
        if not filename_map and not hash_map:
            if len(chunk_maps) >= 2:
                map1_values = list(chunk_maps[0].values())[:10]
                map2_values = list(chunk_maps[1].values())[:10]
                map1_has_names = any('_' in v or '-' in v or len(v) > 15 for v in map1_values)
                map2_has_names = any('_' in v or '-' in v or len(v) > 15 for v in map2_values)
                
                if map1_has_names and not map2_has_names:
                    filename_map = chunk_maps[0]
                    hash_map = chunk_maps[1]
                elif map2_has_names and not map1_has_names:
                    filename_map = chunk_maps[1]
                    hash_map = chunk_maps[0]
                else:
                    filename_map = chunk_maps[0]
                    hash_map = chunk_maps[1]
            elif len(chunk_maps) == 1:
                values = list(chunk_maps[0].values())[:10]
                has_names = any('_' in v or '-' in v or len(v) > 15 for v in values)
                if has_names:
                    filename_map = chunk_maps[0]
                else:
                    hash_map = chunk_maps[0]
        
        # Get all unique chunk IDs
        all_chunk_ids = set()
        if filename_map:
            all_chunk_ids.update(filename_map.keys())
        if hash_map:
            all_chunk_ids.update(hash_map.keys())
        
        if not all_chunk_ids:
            return
        
        for chunk_id in all_chunk_ids:
            filename = filename_map.get(chunk_id, '')
            hash_val = hash_map.get(chunk_id, '')
            
            # Format 1: filename.hash.js
            if filename and hash_val:
                url = f"{public_path.rstrip('/')}/{filename}.{hash_val}{suffix}"
                if self._add_js(url, 'webpack_chunk_enhanced', page_url):
                    generated += 1
            
            # Format 2: chunkId.hash.js (雪瞳's key strategy!)
            if hash_val:
                url = f"{public_path.rstrip('/')}/{chunk_id}.{hash_val}{suffix}"
                if self._add_js(url, 'webpack_chunk_enhanced', page_url):
                    generated += 1
        
        if generated > 0:
            self.on_log(f"  [+] Generated {generated} webpack chunk URLs (generic)")
    
    def _extract_chunk_maps_generic(self, content: str, base_url: str):
        """Generic: extract chunk maps from entire content."""
        obj_pattern = re.compile(
            r'\{((?:["\']?\w+["\']?\s*:\s*["\'][^"\']+["\'][,\s]*){3,})\}\s*\[\s*\w+\s*\]'
        )
        
        chunk_maps = []
        for match in obj_pattern.finditer(content):
            obj_content = match.group(1)
            pairs = re.findall(r'["\']?(\w+)["\']?\s*:\s*["\']([^"\']+)["\']', obj_content)
            if pairs and len(pairs) >= 3:
                chunk_maps.append(dict(pairs))
        
        if chunk_maps:
            self.webpack_chunk_maps = chunk_maps
            
            # Try to separate filename and hash maps
            if len(chunk_maps) >= 2:
                map1_values = list(chunk_maps[0].values())[:10]
                map2_values = list(chunk_maps[1].values())[:10]
                map1_has_names = any('_' in v or '-' in v or len(v) > 15 for v in map1_values)
                map2_has_names = any('_' in v or '-' in v or len(v) > 15 for v in map2_values)
                
                if map1_has_names and not map2_has_names:
                    self.webpack_filename_map = chunk_maps[0]
                    self.webpack_hash_map = chunk_maps[1]
                elif map2_has_names and not map1_has_names:
                    self.webpack_filename_map = chunk_maps[1]
                    self.webpack_hash_map = chunk_maps[0]
                else:
                    self.webpack_filename_map = chunk_maps[0]
                    self.webpack_hash_map = chunk_maps[1]
            elif len(chunk_maps) == 1:
                values = list(chunk_maps[0].values())[:10]
                has_names = any('_' in v or '-' in v or len(v) > 15 for v in values)
                if has_names:
                    self.webpack_filename_map = chunk_maps[0]
                else:
                    self.webpack_hash_map = chunk_maps[0]
    
    def _analyze_external_js(self, depth: int):
        """Download and analyze external JS files"""
        js_to_analyze = [
            js for js in self.extracted_js 
            if js.url not in self.visited_urls and js.content is None
        ]
        
        def fetch_and_analyze(js: ExtractedJS):
            if js.url in self.visited_urls:
                return
            self.visited_urls.add(js.url)
            
            content = self._fetch_js(js.url)
            if not content:
                return
            
            js.content = content
            self._extract_dynamic_urls(content, js.url, 'external_js')
            self._extract_webpack_config(content, js.url)
            self._extract_webpack_runtime_info(content, js.url)
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(fetch_and_analyze, js): js 
                for js in js_to_analyze[:20]
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass
        
        if depth > 1:
            remaining = [js for js in self.extracted_js if js.url not in self.visited_urls]
            if remaining:
                self._analyze_external_js(depth - 1)
    
    def _generate_webpack_chunks(self, page_url: str):
        """Generate Webpack chunk URLs from existing chunk patterns."""
        existing_chunk_url = None
        for js in self.extracted_js:
            if 'chunk-' in js.url and js.source_type == 'script_tag':
                existing_chunk_url = js.url
                break
        
        if not existing_chunk_url:
            return
        
        parsed = urllib.parse.urlparse(existing_chunk_url)
        base_path = parsed.path.rsplit('chunk-', 1)[0]
        self.webpack_public_path = f"{parsed.scheme}://{parsed.netloc}{base_path}"
        
        hash_value = None
        for js in self.extracted_js:
            hash_match = re.search(r'\.(\d{10,13})\.js', js.url)
            if hash_match:
                hash_value = hash_match.group(1)
                break
        
        if not hash_value:
            return
        
        chunk_names_from_app = []
        for js in self.extracted_js:
            if js.content and ('app' in js.url.lower() or 'main' in js.url.lower()):
                chunk_matches = re.findall(r'["\']((?:chunk-)?[a-zA-Z0-9-]{6,20})["\']', js.content)
                for name in chunk_matches:
                    if 'chunk' in name.lower() or len(name) > 8:
                        if name not in chunk_names_from_app:
                            chunk_names_from_app.append(name)
        
        common_chunks = ['chunk-66e743cf', 'chunk-787e9ff8']
        
        for name in chunk_names_from_app[:10]:
            if name not in common_chunks:
                common_chunks.append(name)
        
        public_path = self.webpack_public_path.rstrip('/')
        for chunk_name in common_chunks:
            url = f"{public_path}/{chunk_name}.{hash_value}.js"
            already_exists = any(js.url.split('?')[0] == url for js in self.extracted_js)
            if not already_exists:
                self._add_js(url, 'webpack_chunk_inferred', page_url)
    
    def _clean_dynamic_url(self, url: str, code: str, position: int) -> Optional[str]:
        """Clean and validate dynamically extracted URL"""
        url = url.strip('"\'')
        
        if not url or url.startswith(('#', 'javascript:', 'data:')):
            return None
        
        if not ('/' in url or url.startswith('http') or url.endswith('.js')):
            return None
        
        return url
    
    def _add_js(self, url: str, source_type: str, parent_url: str, line_number: int = None) -> bool:
        """Add a JS file to the collection. Returns True if added, False if duplicate."""
        url = url.split('#')[0]
        url_for_dedup = url.split('?')[0]
        
        for existing in self.extracted_js:
            if existing.url.split('?')[0] == url_for_dedup:
                return False
        
        self.extracted_js.append(ExtractedJS(
            url=url,
            source_type=source_type,
            parent_url=parent_url,
            line_number=line_number
        ))
        return True
    
    def _fetch_js(self, url: str) -> Optional[str]:
        """Fetch JS file content"""
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            resp.raise_for_status()
            
            ct = resp.headers.get('Content-Type', '')
            if 'javascript' not in ct and 'ecmascript' not in ct:
                if not url.endswith(('.js', '.mjs', '.cjs')):
                    return None
            
            if len(resp.content) > 5 * 1024 * 1024:
                return None
            
            return resp.text
        except Exception:
            return None
    
    def _resolve_url(self, base: str, href: str) -> Optional[str]:
        """Resolve relative URL to absolute"""
        if not href:
            return None
        
        href = href.strip()
        
        if href.startswith(('data:', 'javascript:', 'mailto:', 'tel:', '#')):
            return None
        
        if href.startswith('//'):
            parsed = urllib.parse.urlparse(base)
            return f"{parsed.scheme}:{href}"
        
        if href.startswith(('http://', 'https://')):
            return href
        
        return urllib.parse.urljoin(base, href)
    
    def _is_js_url(self, url: str) -> bool:
        """Check if URL likely points to a JS file"""
        path = urllib.parse.urlparse(url).path.lower()
        
        skip_exts = {'css', 'png', 'jpg', 'jpeg', 'svg', 'gif', 'webp', 'ico', 
                     'pdf', 'zip', 'woff', 'woff2', 'ttf', 'eot'}
        ext = path.split('.')[-1] if '.' in path.split('/')[-1] else ''
        if ext in skip_exts:
            return False
        
        js_exts = {'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx'}
        if ext in js_exts:
            return True
        
        if not ext:
            return True
        
        return False
    
    def _deduplicate(self) -> List[ExtractedJS]:
        """Remove duplicate JS files"""
        seen = {}
        unique = []
        
        for js in self.extracted_js:
            url_key = js.url.split('?')[0]
            if url_key not in seen:
                seen[url_key] = js
                unique.append(js)
        
        return unique
    
    def get_statistics(self) -> Dict:
        """Get extraction statistics"""
        stats = {
            'total': len(self.extracted_js),
            'by_type': {},
            'webpack_info': {
                'public_path': self.webpack_public_path,
                'chunk_global': self.webpack_chunk_global,
                'chunk_maps_count': len(self.webpack_chunk_maps) if self.webpack_chunk_maps else 0,
                'url_suffix': self.webpack_url_suffix,
                'filename_map_count': len(self.webpack_filename_map) if self.webpack_filename_map else 0,
                'hash_map_count': len(self.webpack_hash_map) if self.webpack_hash_map else 0,
            }
        }
        
        for js in self.extracted_js:
            stats['by_type'][js.source_type] = stats['by_type'].get(js.source_type, 0) + 1
        
        return stats


class PlaywrightJSExtractor:
    """
    Headless browser-based JS extractor.
    Real-time network monitoring approach (like 雪瞳's chrome.webRequest).
    Captures ALL JS files loaded during page lifecycle.
    """
    
    def __init__(self):
        self.extracted_urls: Set[str] = set()
        self.all_resources: List[Dict] = []
    
    async def extract(self, url: str, timeout: int = 60000, cookie: str = '') -> List[Dict]:
        """
        Extract all JS files by monitoring network requests.
        Similar to 雪瞳's chrome.webRequest.onBeforeRequest monitoring.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise ImportError(
                "Playwright is required for browser-based extraction. "
                "Install with: pip install playwright && playwright install chromium"
            )
        
        js_resources = []
        seen_urls = set()
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            
            # Set cookies if provided
            if cookie:
                try:
                    cookies = []
                    for item in cookie.split(';'):
                        item = item.strip()
                        if '=' in item:
                            name, value = item.split('=', 1)
                            cookies.append({
                                'name': name.strip(),
                                'value': value.strip(),
                                'domain': url.split('/')[2] if '/' in url else '',
                                'path': '/'
                            })
                    if cookies:
                        await context.add_cookies(cookies)
                except Exception:
                    pass
            
            page = await context.new_page()
            
            # Core: real-time monitoring of ALL network responses (like 雪瞳's webRequest)
            async def on_response(response):
                """Monitor all responses, capture JS files"""
                try:
                    resp_url = response.url
                    
                    if resp_url in seen_urls:
                        return
                    
                    is_js = False
                    
                    # Method 1: resource type
                    try:
                        if response.request.resource_type == 'script':
                            is_js = True
                    except Exception:
                        pass
                    
                    # Method 2: Content-Type
                    try:
                        content_type = response.headers.get('content-type', '')
                        if 'javascript' in content_type or 'ecmascript' in content_type:
                            is_js = True
                    except Exception:
                        pass
                    
                    # Method 3: URL extension
                    if not is_js:
                        url_path = resp_url.split('?')[0].split('#')[0].lower()
                        if url_path.endswith(('.js', '.mjs', '.cjs', '.jsx', '.tsx')):
                            is_js = True
                        if '.async.js' in url_path:
                            is_js = True
                        if '.chunk.js' in url_path:
                            is_js = True
                    
                    if is_js and not resp_url.startswith('data:'):
                        seen_urls.add(resp_url)
                        js_resources.append({
                            'url': resp_url,
                            'source': 'browser_network',
                            'content_type': response.headers.get('content-type', ''),
                            'status': response.status,
                        })
                except Exception:
                    pass
            
            # Register response listener (like 雪瞳's chrome.webRequest.onHeadersReceived)
            page.on('response', on_response)
            
            try:
                # Phase 1: Load page
                await page.goto(url, wait_until='networkidle', timeout=timeout)
                await page.wait_for_timeout(3000)
                
                # Phase 2: Scroll to trigger lazy loading
                try:
                    await page.evaluate('''
                        async () => {
                            const delay = ms => new Promise(r => setTimeout(r, ms));
                            const scrollHeight = document.body.scrollHeight;
                            for (let i = 0; i < scrollHeight; i += 300) {
                                window.scrollTo(0, i);
                                await delay(100);
                            }
                            window.scrollTo(0, 0);
                            await delay(500);
                            for (let i = 0; i < scrollHeight; i += 500) {
                                window.scrollTo(0, i);
                                await delay(50);
                            }
                        }
                    ''')
                    await page.wait_for_timeout(2000)
                except Exception:
                    pass
                
                # Phase 3: Extract script src from DOM
                try:
                    script_srcs = await page.evaluate('''
                        () => {
                            const scripts = document.querySelectorAll('script[src]');
                            return Array.from(scripts).map(s => s.src).filter(Boolean);
                        }
                    ''')
                    for src in script_srcs:
                        if src not in seen_urls and not src.startswith('data:'):
                            seen_urls.add(src)
                            js_resources.append({
                                'url': src,
                                'source': 'browser_dom',
                                'content_type': '',
                                'status': 200,
                            })
                except Exception:
                    pass
                
                # Phase 4: Extract preload links
                try:
                    preload_srcs = await page.evaluate('''
                        () => {
                            const links = document.querySelectorAll('link[as="script"][href], link[rel="modulepreload"][href]');
                            return Array.from(links).map(l => l.href).filter(Boolean);
                        }
                    ''')
                    for src in preload_srcs:
                        if src not in seen_urls and not src.startswith('data:'):
                            seen_urls.add(src)
                            js_resources.append({
                                'url': src,
                                'source': 'browser_preload',
                                'content_type': '',
                                'status': 200,
                            })
                except Exception:
                    pass
                
                # Phase 5: Wait for delayed loads
                try:
                    await page.wait_for_load_state('networkidle', timeout=10000)
                except Exception:
                    pass
                
                await page.wait_for_timeout(2000)
                
            except Exception as e:
                print(f"Warning: Page load error: {e}")
            
            finally:
                await browser.close()
        
        return js_resources


def extract_js_files(
    html_content: str,
    page_url: str,
    headers: dict,
    use_browser: bool = False,
    depth: int = 2,
    cookie: str = '',
    on_log=None
) -> Tuple[List[Dict], Dict]:
    """
    Main function to extract all JS files.
    Combines static analysis + browser-based real-time monitoring.
    """
    all_js_urls = set()
    js_info = []
    
    # Method 1: Static extraction
    extractor = DynamicJSExtractor(page_url, headers, on_log=on_log)
    extracted = extractor.extract_all_js(html_content, page_url, depth)
    
    target_domain = urllib.parse.urlparse(page_url).netloc
    
    for js in extracted:
        url_key = js.url.split('?')[0]
        if url_key not in all_js_urls:
            js_domain = urllib.parse.urlparse(js.url).netloc
            if js_domain and js_domain != target_domain:
                continue
            all_js_urls.add(url_key)
            js_info.append({
                'url': js.url,
                'source': js.source_type,
                'parent': js.parent_url
            })
    
    stats = extractor.get_statistics()
    
    # Method 2: Browser-based extraction (real-time network monitoring)
    if use_browser:
        try:
            import asyncio
            browser_extractor = PlaywrightJSExtractor()
            browser_resources = asyncio.run(browser_extractor.extract(page_url, cookie=cookie))
            
            for resource in browser_resources:
                url_key = resource['url'].split('?')[0]
                if url_key not in all_js_urls:
                    js_domain = urllib.parse.urlparse(resource['url']).netloc
                    if js_domain and js_domain != target_domain:
                        continue
                    all_js_urls.add(url_key)
                    js_info.append({
                        'url': resource['url'],
                        'source': resource.get('source', 'browser_network'),
                        'parent': page_url
                    })
            
            stats['browser_extracted'] = len(browser_resources)
            stats['browser_by_source'] = {}
            for r in browser_resources:
                src = r.get('source', 'unknown')
                stats['browser_by_source'][src] = stats['browser_by_source'].get(src, 0) + 1
        except Exception as e:
            stats['browser_error'] = str(e)
    
    stats['unique_urls'] = len(all_js_urls)
    
    return js_info, stats