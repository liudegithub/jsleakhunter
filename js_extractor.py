"""
JSLeakHunter — Enhanced JavaScript Extractor
Comprehensive JS file discovery including dynamic loading
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
    
    def __init__(self, base_url: str, headers: dict, timeout: int = 15, verify_ssl: bool = False):
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
    
    def extract_all_js(self, html_content: str, page_url: str, depth: int = 2) -> List[ExtractedJS]:
        """Main entry point: Extract all JS files from a page and its resources"""
        self.extracted_js = []
        self.visited_urls = set()
        self.webpack_public_path = None
        self.webpack_hash_pattern = None
        
        # Phase 1: Extract from HTML
        self._extract_from_html(html_content, page_url)
        
        # Phase 2: Analyze inline scripts for dynamic loading
        self._analyze_inline_scripts(html_content, page_url)
        
        # Phase 3: Download and analyze external JS files
        if depth > 0:
            self._analyze_external_js(depth)
        
        # Phase 4: Generate Webpack chunk URLs based on discovered patterns
        self._generate_webpack_chunks(page_url)
        
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
        # Find publicPath
        public_path_match = re.search(r'''__webpack_require__\.p\s*=\s*["']([^"']+)["']''', code)
        if public_path_match:
            self.webpack_public_path = public_path_match.group(1)
            if self.webpack_public_path.startswith('./') or self.webpack_public_path.startswith('/'):
                self.webpack_public_path = self._resolve_url(base_url, self.webpack_public_path)
        
        # Find chunk hash pattern
        hash_match = re.search(r'''\+\s*["']\.(\d{10,13}\.js)["']''', code)
        if hash_match:
            self.webpack_hash_pattern = hash_match.group(1)
    
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
        """
        Generate Webpack chunk URLs based on discovered patterns
        Only generate the MOST LIKELY path to reduce noise
        """
        # Find existing chunk URL to determine the correct base path
        existing_chunk_url = None
        for js in self.extracted_js:
            if 'chunk-' in js.url and js.source_type == 'script_tag':
                existing_chunk_url = js.url
                break
        
        if not existing_chunk_url:
            # No existing chunk found, cannot determine path
            return
        
        # Extract the exact base path from existing URL
        # e.g., https://domain.com/static/js/chunk-xxx.js -> https://domain.com/static/js/
        parsed = urllib.parse.urlparse(existing_chunk_url)
        base_path = parsed.path.rsplit('chunk-', 1)[0]
        self.webpack_public_path = f"{parsed.scheme}://{parsed.netloc}{base_path}"
        
        # Extract hash from existing chunk URLs
        hash_value = None
        for js in self.extracted_js:
            hash_match = re.search(r'\.(\d{10,13})\.js', js.url)
            if hash_match:
                hash_value = hash_match.group(1)
                break
        
        if not hash_value:
            return
        
        # Extract chunk names from app.js content if available
        chunk_names_from_app = []
        for js in self.extracted_js:
            if js.content and ('app' in js.url.lower() or 'main' in js.url.lower()):
                # Look for chunk names in the content
                # Pattern: "chunk-66e743cf" or chunkId
                chunk_matches = re.findall(r'["\']((?:chunk-)?[a-zA-Z0-9-]{6,20})["\']', js.content)
                for name in chunk_matches:
                    if 'chunk' in name.lower() or len(name) > 8:
                        if name not in chunk_names_from_app:
                            chunk_names_from_app.append(name)
        
        # Common chunk patterns (only the most likely ones)
        common_chunks = [
            'chunk-66e743cf',
            'chunk-787e9ff8',
        ]
        
        # Add chunks discovered from app.js
        for name in chunk_names_from_app[:10]:  # Limit to 10
            if name not in common_chunks:
                common_chunks.append(name)
        
        # Generate URLs using the discovered base path
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
        
        # Skip if it doesn't look like a URL
        if not ('/' in url or url.startswith('http') or url.endswith('.js')):
            return None
        
        return url
    
    def _add_js(self, url: str, source_type: str, parent_url: str, line_number: int = None):
        """Add a JS file to the collection"""
        url = url.split('#')[0]
        url_for_dedup = url.split('?')[0]
        
        for existing in self.extracted_js:
            if existing.url.split('?')[0] == url_for_dedup:
                return
        
        self.extracted_js.append(ExtractedJS(
            url=url,
            source_type=source_type,
            parent_url=parent_url,
            line_number=line_number
        ))
    
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
            'by_type': {}
        }
        
        for js in self.extracted_js:
            stats['by_type'][js.source_type] = stats['by_type'].get(js.source_type, 0) + 1
        
        return stats


class PlaywrightJSExtractor:
    """Headless browser-based JS extractor"""
    
    def __init__(self):
        self.extracted_urls: Set[str] = set()
    
    async def extract(self, url: str, timeout: int = 30000) -> List[Dict]:
        """Extract all JS files by monitoring network requests"""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise ImportError(
                "Playwright is required for browser-based extraction. "
                "Install with: pip install playwright && playwright install chromium"
            )
        
        js_resources = []
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            
            async def handle_response(response):
                resp_url = response.url
                content_type = response.headers.get('content-type', '')
                
                if response.request.resource_type == 'script' or 'javascript' in content_type:
                    if resp_url not in self.extracted_urls:
                        self.extracted_urls.add(resp_url)
                        js_resources.append({
                            'url': resp_url,
                            'source': 'browser_network',
                            'content_type': content_type
                        })
            
            page.on('response', handle_response)
            
            try:
                await page.goto(url, wait_until='networkidle', timeout=timeout)
                await page.wait_for_timeout(3000)
                
                # Scroll to trigger lazy loading
                await page.evaluate('''
                    async () => {
                        const scrollHeight = document.body.scrollHeight;
                        for (let i = 0; i < scrollHeight; i += 300) {
                            window.scrollTo(0, i);
                            await new Promise(r => setTimeout(r, 100));
                        }
                        window.scrollTo(0, 0);
                    }
                ''')
                
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
    depth: int = 2
) -> Tuple[List[Dict], Dict]:
    """
    Main function to extract all JS files
    """
    all_js_urls = set()
    js_info = []
    
    # Method 1: Static extraction
    extractor = DynamicJSExtractor(page_url, headers)
    extracted = extractor.extract_all_js(html_content, page_url, depth)
    
    # 获取目标域名
    target_domain = urllib.parse.urlparse(page_url).netloc
    
    for js in extracted:
        url_key = js.url.split('?')[0]
        if url_key not in all_js_urls:
            # 过滤第三方外部资源，只保留目标网站自身的JS
            js_domain = urllib.parse.urlparse(js.url).netloc
            if js_domain and js_domain != target_domain:
                continue  # 跳过外部域名
            
            all_js_urls.add(url_key)
            js_info.append({
                'url': js.url,
                'source': js.source_type,
                'parent': js.parent_url
            })
    
    stats = extractor.get_statistics()
    
    # Method 2: Browser-based extraction (optional)
    if use_browser:
        try:
            import asyncio
            browser_extractor = PlaywrightJSExtractor()
            browser_resources = asyncio.run(browser_extractor.extract(page_url))
            
            for resource in browser_resources:
                url_key = resource['url'].split('?')[0]
                if url_key not in all_js_urls:
                    # 过滤第三方外部资源
                    js_domain = urllib.parse.urlparse(resource['url']).netloc
                    if js_domain and js_domain != target_domain:
                        continue
                    
                    all_js_urls.add(url_key)
                    js_info.append({
                        'url': resource['url'],
                        'source': 'browser_network',
                        'parent': page_url
                    })
            
            stats['browser_extracted'] = len(browser_resources)
        except Exception as e:
            stats['browser_error'] = str(e)
    
    stats['unique_urls'] = len(all_js_urls)
    
    return js_info, stats