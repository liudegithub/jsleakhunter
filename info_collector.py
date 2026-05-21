"""
JSLeakHunter — Information Collector v1.1
Based on 雪瞳's detection logic from content.js
Collects: domains, IPs, phones, emails, ID cards, JWTs, credentials,
          companies, GitHub URLs, URLs, API paths, routes
NEVER skip - collect everything, filter later
宁可误报100个，不能漏扫一个
"""

import re
from typing import Dict, List, Set, Optional


# ============================================================
# 域名TLD列表 (from 雪瞳)
# ============================================================
DOMAIN_TLDS = (
    'wang|club|xyz|vip|top|beer|work|ren|technology|fashion|luxe|yoga|red|'
    'love|online|ltd|chat|group|pub|run|city|live|kim|pet|space|site|tech|'
    'host|fun|store|pink|ski|design|ink|wiki|video|email|company|plus|center|'
    'cool|fund|gold|guru|life|team|today|world|zone|social|bio|black|blue|'
    'green|lotto|organic|poker|promo|vote|archi|voto|fit|cn|website|press|'
    'icu|art|law|shop|band|media|cab|cash|cafe|games|link|fan|net|cc|com|'
    'fans|cloud|info|pro|mobi|asia|studio|biz|vin|news|fyi|tax|tv|market|'
    'shopping|mba|sale|co|org'
)


# ============================================================
# 域名过滤黑名单 (from 雪瞳)
# ============================================================
DOMAIN_BLACKLIST = [
    'el.datepicker.today', 'obj.style.top', 'window.top',
    'mydragdiv.style.top', 'container.style.top', 'location.host',
    'page.info', 'res.info', 'item.info',
]


# ============================================================
# 中文黑名单 (from 雪瞳)
# ============================================================
CHINESE_BLACKLIST = {
    '请', '输入', '前往', '整个', '常用', '咨询', '为中心', '是否',
    '以上', '目前', '任务', '或者', '推动', '需要', '直接', '识别',
    '获取', '用于', '清除', '遍历', '使用', '是由', '您', '用户',
    '一家', '项目', '等', '造价', '判断', '通过', '为了', '可以',
    '掌握', '传统', '杀毒', '允许', '分析', '包括', '很多', '接',
    '未经', '方式', '些', '的', '第三方', '因此', '形式', '任何',
    '提交', '多数', '其他', '执行', '操作', '维护', '或', '其它',
    '分享', '导致', '一概', '所有', '及其', '以及', '应当', '条件',
    '除非', '否则', '违反', '将被', '提供', '无法', '建立', '打造',
    '帮助', '依法', '鉴于', '快速', '构建', '是', '在', '去',
    '恶意', '挖矿', '流氓', '勒索', '依靠', '基于', '通常',
}


# ============================================================
# 特殊IP范围 (from 雪瞳)
# ============================================================
SPECIAL_IP_PATTERNS = [
    re.compile(r'^0\.0\.0\.0$'),
    re.compile(r'^255\.255\.255\.255$'),
]


# ============================================================
# 文件分类模式
# ============================================================
IMAGE_PATTERN = re.compile(
    r'\.(?:jpg|jpeg|png|gif|bmp|webp|svg|ico|mp3|mp4|m4a|wav|swf)(?:\?[^\'\"]*)?$',
    re.IGNORECASE
)
JS_FILE_PATTERN = re.compile(
    r'\.(?:js|jsx|ts|tsx|less)(?:\?[^\'\"]*)?$',
    re.IGNORECASE
)
DOC_FILE_PATTERN = re.compile(
    r'\.(?:pdf|doc|docx|xls|xlsx|ppt|exe|apk|zip|7z|dll|dmg|pptx|txt|rar|md|csv)(?:\?[^\'\"]*)?$',
    re.IGNORECASE
)
FONT_PATTERN = re.compile(
    r'\.(?:ttf|eot|woff|woff2|otf|css)(?:\?[^\'\"]*)?$',
    re.IGNORECASE
)


# ============================================================
# API路径过滤内容类型
# ============================================================
FILTERED_CONTENT_TYPES = [
    'multipart/form-data', 'node_modules/', 'pause/break',
    'partial/ajax', 'chrome/', 'firefox/', 'edge/',
    'examples/element-ui', 'static/js/', 'static/css/',
    'stylesheet/less', 'jpg/jpeg/png/pdf',
    'yyyy/mm/dd', 'dd/mm/yyyy', 'mm/dd/yy', 'yy/mm/dd',
    'm/d/Y', 'm/d/y', 'xx/xx', 'zrender/vml/vml',
]


# ============================================================
# 内容过滤值 (from 雪瞳)
# ============================================================
SHORT_VALUES = {
    'up', 'in', 'by', 'of', 'is', 'on', 'to', 'no', 'age', 'all', 'app',
    'ang', 'bar', 'bea', 'big', 'bug', 'can', 'com', 'con', 'cry', 'dom',
    'dow', 'emp', 'ent', 'eta', 'eye', 'for', 'get', 'gen', 'has', 'hei',
    'hid', 'ing', 'int', 'ken', 'key', 'lea', 'log', 'low', 'met', 'mod',
    'new', 'nor', 'not', 'num', 'red', 'obj', 'old', 'out', 'pic', 'pre',
    'pro', 'pop', 'pun', 'put', 'rad', 'ran', 'ref', 'red', 'reg', 'ren',
    'rig', 'row', 'sea', 'set', 'seq', 'shi', 'str', 'sub', 'sup', 'sun',
    'tab', 'tan', 'tip', 'top', 'uri', 'url', 'use', 'ver', 'via', 'rce',
    'sum', 'bit', 'kit', 'uid',
}

MEDIUM_VALUES = {
    'null', 'node', 'when', 'face', 'read', 'load', 'body', 'left',
    'mark', 'down', 'ctrl', 'play', 'ntal', 'head', 'item', 'init',
    'hand', 'next', 'nect', 'json', 'long', 'slid', 'less', 'view',
    'html', 'tion', 'rect', 'link', 'char', 'core', 'turn', 'atom',
    'tech', 'type', 'main', 'size', 'time', 'full', 'card', 'more',
    'wrap', 'this', 'tool', 'late', 'note', 'leng', 'area', 'bool',
    'pick', 'parm', 'axis', 'high', 'true', 'date', 'tend', 'work',
    'lang', 'func', 'able', 'dark', 'term', 'info', 'data', 'opts',
    'self', 'void', 'pace', 'list', 'brac', 'cret', 'tive', 'sult',
    'text', 'stor', 'back', 'port', 'case', 'pare', 'dent', 'blot',
    'fine', 'reif', 'cord', 'else', 'fail', 'rend', 'leav', 'hint',
    'coll', 'move', 'with', 'base', 'rate', 'name', 'hile', 'lete',
    'post', 'pect', 'icon', 'auth', 'jump', 'wave', 'land', 'wood',
    'lize', 'room', 'chat', 'user', 'vice', 'ress', 'line', 'send',
    'mess', 'calc', 'http', 'rame', 'rest', 'last', 'guar', 'iate',
    'ment', 'task', 'stat', 'fill', 'coun', 'faul', 'rece', 'arse',
    'exam', 'good', 'gest', 'word', 'cast', 'lock', 'slot', 'fund',
    'plus', 'thre', 'sign', 'pack', 'reak', 'code', 'tent', 'math',
    'lect', 'draw', 'lend', 'glow', 'past', 'blue', 'dial', 'purp',
}

LONG_VALUES = {
    'about', 'alias', 'apply', 'array', 'basic', 'beare', 'begin',
    'black', 'break', 'broad', 'catch', 'class', 'close', 'clear',
    'click', 'clude', 'color', 'count', 'cover', 'croll', 'crypt',
    'error', 'false', 'fault', 'fetch', 'final', 'found', 'gener',
    'green', 'group', 'guard', 'index', 'inner', 'input', 'inter',
    'light', 'login', 'opera', 'param', 'parse', 'panel', 'place',
    'print', 'phony', 'radio', 'range', 'right', 'refer', 'serve',
    'share', 'shift', 'style', 'tance', 'title', 'token', 'tract',
    'trans', 'trave', 'valid', 'video', 'white', 'write', 'button',
    'cancel', 'create', 'double', 'finger', 'global', 'insert',
    'module', 'normal', 'object', 'popper', 'triple', 'search',
    'select', 'simple', 'single', 'status', 'statis', 'switch',
    'system', 'visual', 'verify', 'detail', 'screen', 'member',
    'change', 'buffer', 'grade',
}

KEY_BLACKLIST = {
    'size', 'row', 'dict', 'up', 'highlight', 'cabin', 'cross', 'time',
}


# ============================================================
# 需要过滤的API前缀 (text/ 和 application/ 的MIME类型)
# ============================================================
API_MIME_PREFIXES = ['text/', 'application/']


class InfoCollector:
    """
    Collects information from web page content.
    Based on 雪瞳's content.js detection logic.
    宁可误报100个，不能漏扫一个
    """

    # ============================================================
    # 核心正则模式
    # ============================================================

    # 域名模式
    RE_DOMAIN = re.compile(
        rf'\b(?:(?!this)[a-z0-9%-]+\.)*?(?:(?!this)[a-z0-9%-]{{2,}}\.)'
        rf'(?:{DOMAIN_TLDS})(?::\d{{1,5}})?'
        rf'(?![a-zA-Z0-9._=>();!}}\-])\b',
        re.IGNORECASE
    )

    # 域名过滤器
    RE_DOMAIN_FILTER = re.compile(
        r'\b(?:[a-zA-Z0-9%-]+\.)+[a-z]{2,10}(?::\d{1,5})?\b'
    )

    # IP模式
    RE_IP = re.compile(
        r'(?<!\.|\d)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?::\d{1,5})?(?!\.|[0-9])'
    )

    # 手机号模式
    RE_PHONE = re.compile(
        r'(?<!\d|\.)(?:13[0-9]|14[01456879]|15[0-35-9]|16[2567]|17[0-8]|'
        r'18[0-9]|19[0-35-9]|198|199)\d{8}(?!\d)'
    )

    # 邮箱模式
    RE_EMAIL = re.compile(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+(?!\.png)\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?'
    )

    # 身份证模式
    RE_IDCARD = re.compile(
        r'(?:\d{6}(?:19|20)(?:0\d|10|11|12)(?:[0-2]\d|30|31)\d{3}$)|'
        r'(?:\d{6}(?:18|19|20)\d{2}(?:0[1-9]|10|11|12)(?:[0-2]\d|30|31)\d{3}(?:\d|X|x))(?!\d)'
    )

    # JWT模式
    RE_JWT = re.compile(
        r'["\'](?:ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|'
        r'ey[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,})["\']'
    )

    # URL模式
    RE_URL = re.compile(
        r'(?:https?|wss?|ftp):\/\/(?:(?:[\w-]+\.)+[a-z]{2,}|'
        r'(?:\d{1,3}\.){3}\d{1,3})(?::\d{2,5})?(?:\/[^\s>)\}<\'\"]*)?',
        re.IGNORECASE
    )

    # 公司名模式
    RE_COMPANY = re.compile(
        r'(?:[\u4e00-\u9fa5\（\）]{4,15}[^的](?:公司|中心)|'
        r'[\u4e00-\u9fa5\（\）]{2,10}[^的](?:软件)|'
        r'[\u4e00-\u9fa5]{2,15}(?:科技|集团))(?!法|点|与|查)'
    )

    # GitHub URL模式
    RE_GITHUB = re.compile(
        r'(?:https?:\/\/)?(?:www\.)?github\.com\/[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+',
        re.IGNORECASE
    )

    # API路径模式
    # 修复: 将(?<!text|application)拆分为两部分
    # Part 1: 绝对路径 /xxx/xxx
    RE_API_ABSOLUTE = re.compile(
        r'''["'`](?:\/|\.\.\/|\.\/)[^\/\>\< \)\(\}\,\'"\\](?:[^\^\>\< \)\(\,\'"\\])*?["'`]'''
    )
    # Part 2: 相对路径 xxx/xxx (排除MIME类型)
    RE_API_RELATIVE = re.compile(
        r'''["'`][a-zA_Z0-9]+\/(?:[^\^\>\< \)\(\{\}\,\'"\\])*?["'`]'''
    )

    # 凭证模式1
    RE_CREDENTIAL_MODE1 = re.compile(
        r'''["']\w*(?:pwd|pass|user|member|account|password|passwd|admin|root|system)'''
        r'''[_-]?(?:id|name)?[0-9]*["']'''
        r'''\s*[:=]\s*(?:["'][^,"'\s\(]*["'])''',
        re.IGNORECASE
    )

    # 凭证模式2
    RE_CREDENTIAL_MODE2 = re.compile(
        r'''\w*(?:pwd|pass|user|member|account|password|passwd|admin|root|system)'''
        r'''[_-]?(?:id|name)?[0-9]*'''
        r'''\s*[:=]\s*(?:["'][^,"'\s\(]*["'])''',
        re.IGNORECASE
    )

    # 凭证模式3
    RE_CREDENTIAL_MODE3 = re.compile(
        r'''["']\w*(?:pwd|pass|user|member|account|password|passwd|admin|root|system)'''
        r'''[_-]?(?:id|name)?[0-9]*'''
        r'''\s*[:=]\s*(?:[^,"'\s\(]*)["']''',
        re.IGNORECASE
    )

    # ID密钥模式 (from 雪瞳)
    ID_KEY_PATTERNS = [
        {'name': '微信开放平台密钥', 'pattern': re.compile(r'wx[a-z0-9]{15,18}')},
        {'name': 'AWS密钥', 'pattern': re.compile(r'AKIA[0-9A-Z]{16}')},
        {'name': '阿里云密钥', 'pattern': re.compile(r'LTAI[A-Za-z\d]{12,30}')},
        {'name': 'Google API密钥', 'pattern': re.compile(r'AIza[0-9A-Za-z_\-]{35}')},
        {'name': '腾讯云密钥', 'pattern': re.compile(r'AKID[A-Za-z\d]{13,40}')},
        {'name': '京东云密钥', 'pattern': re.compile(r'JDC_[0-9A-Z]{25,40}')},
        {'name': '其他AWS密钥', 'pattern': re.compile(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}')},
        {'name': '支付宝开放平台密钥', 'pattern': re.compile(r'(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}')},
        {'name': 'GitLab Token', 'pattern': re.compile(r'glpat-[a-zA-Z0-9\-=_]{20,22}')},
        {'name': 'GitHub Token', 'pattern': re.compile(r'(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255}')},
        {'name': 'Apple开发者密钥', 'pattern': re.compile(r'APID[a-zA-Z0-9]{32,42}')},
        {'name': '企业微信密钥', 'pattern': re.compile(r'ww[a-z0-9]{15,18}')},
    ]

    # 驼峰检测
    CAMEL_CASE_PATTERN = re.compile(r'\b[_a-z]+(?:[A-Z][a-z]+)+\b')

    # 内部路径关键词
    SKIP_API_PREFIXES = re.compile(
        r'^(audio|blots|core|ace|icon|css|formats|image|js|modules|text|themes|ui|video|static|attributors|application)'
    )

    def __init__(self):
        self.collected = {
            'domains': set(),
            'routes': set(),
            'absolute_apis': set(),
            'apis': set(),
            'module_files': set(),
            'doc_files': set(),
            'ips': set(),
            'phones': set(),
            'emails': set(),
            'idcards': set(),
            'jwts': set(),
            'image_files': set(),
            'js_files': set(),
            'vue_files': set(),
            'urls': set(),
            'github_urls': set(),
            'companies': set(),
            'credentials': [],
            'cookies': [],
            'id_keys': [],
        }

    def collect_all(self, content: str, source_url: str) -> Dict:
        """主入口：对内容进行全面信息搜集"""
        self._collect_domains(content, source_url)
        self._collect_ips(content, source_url)
        self._collect_phones(content, source_url)
        self._collect_emails(content, source_url)
        self._collect_idcards(content, source_url)
        self._collect_jwts(content, source_url)
        self._collect_urls(content, source_url)
        self._collect_companies(content, source_url)
        self._collect_github_urls(content, source_url)
        self._collect_credentials(content, source_url)
        self._collect_id_keys(content, source_url)
        self._collect_apis(content, source_url)
        return self.get_summary()

    def _collect_domains(self, content: str, source: str):
        """搜集域名"""
        for match in self.RE_DOMAIN.finditer(content):
            domain = match.group().lower().strip('"\'')
            domain = domain.split('?')[0]
            if any(bl in domain for bl in DOMAIN_BLACKLIST):
                continue
            domain_match = self.RE_DOMAIN_FILTER.match(domain)
            if domain_match:
                domain = domain_match.group(0)
            else:
                continue
            if len(domain) < 4:
                continue
            self.collected['domains'].add(domain)

    def _collect_ips(self, content: str, source: str):
        """搜集IP地址"""
        for match in self.RE_IP.finditer(content):
            ip = match.group().strip('"\'`')
            if any(p.match(ip) for p in SPECIAL_IP_PATTERNS):
                continue
            self.collected['ips'].add(ip)

    def _collect_phones(self, content: str, source: str):
        """搜集手机号"""
        for match in self.RE_PHONE.finditer(content):
            self.collected['phones'].add(match.group())

    def _collect_emails(self, content: str, source: str):
        """搜集邮箱"""
        for match in self.RE_EMAIL.finditer(content):
            email = match.group().lower()
            if email.endswith(('.png', '.jpg', '.gif', '.svg', '.css', '.woff', '.woff2')):
                continue
            self.collected['emails'].add(email)

    def _collect_idcards(self, content: str, source: str):
        """搜集身份证号"""
        for match in self.RE_IDCARD.finditer(content):
            self.collected['idcards'].add(match.group())

    def _collect_jwts(self, content: str, source: str):
        """搜集JWT Token"""
        for match in self.RE_JWT.finditer(content):
            jwt = match.group().strip('"\'')
            self.collected['jwts'].add(jwt)

    def _collect_urls(self, content: str, source: str):
        """搜集URL"""
        for match in self.RE_URL.finditer(content):
            url = match.group()
            if 'github.com' in url.lower():
                self.collected['github_urls'].add(url)
            else:
                self.collected['urls'].add(url)

    def _collect_companies(self, content: str, source: str):
        """搜集公司机构名"""
        for match in self.RE_COMPANY.finditer(content):
            company = match.group()
            if any(bl in company for bl in CHINESE_BLACKLIST):
                continue
            if '\uff08\uff09' in company and not re.search(r'\uff08\S*\uff09', company):
                continue
            self.collected['companies'].add(company)

    def _collect_github_urls(self, content: str, source: str):
        """搜集GitHub链接"""
        for match in self.RE_GITHUB.finditer(content):
            self.collected['github_urls'].add(match.group())

    def _collect_credentials(self, content: str, source: str):
        """搜集凭证信息 (3种模式)"""
        patterns = [self.RE_CREDENTIAL_MODE1, self.RE_CREDENTIAL_MODE2, self.RE_CREDENTIAL_MODE3]
        for pattern in patterns:
            for match in pattern.finditer(content):
                text = match.group()
                if self._validate_credential(text):
                    self.collected['credentials'].append({
                        'type': 'credential',
                        'value': text,
                        'source': source,
                    })

    def _collect_id_keys(self, content: str, source: str):
        """搜集ID密钥"""
        for item in self.ID_KEY_PATTERNS:
            for match in item['pattern'].finditer(content):
                text = match.group()
                if self._validate_id_key(text):
                    self.collected['id_keys'].append({
                        'type': 'id_key',
                        'name': item['name'],
                        'value': text,
                        'source': source,
                    })

    def _collect_apis(self, content: str, source: str):
        """搜集API路径"""
        all_matches = []

        # Part 1: 绝对路径
        for match in self.RE_API_ABSOLUTE.finditer(content):
            all_matches.append(match.group())

        # Part 2: 相对路径 (过滤掉MIME类型)
        for match in self.RE_API_RELATIVE.finditer(content):
            text = match.group()
            # 过滤 text/ 和 application/ 等MIME类型前缀
            # 等价于原来的 (?<!text|application) 后行断言
            inner = text.strip('"\'`')
            skip = False
            for prefix in API_MIME_PREFIXES:
                if prefix in inner.lower():
                    skip = True
                    break
            if not skip:
                all_matches.append(text)

        # 分类处理所有匹配
        for raw in all_matches:
            path = raw.strip('"\'`')

            # 过滤字体文件
            if FONT_PATTERN.search(path):
                continue

            # 分类文件类型
            if path.endswith('.vue'):
                self.collected['vue_files'].add(path)
                continue
            if IMAGE_PATTERN.search(path):
                self.collected['image_files'].add(path)
                continue
            if JS_FILE_PATTERN.search(path):
                self.collected['js_files'].add(path)
                continue
            if DOC_FILE_PATTERN.search(path):
                self.collected['doc_files'].add(path)
                continue

            # 过滤内容类型
            path_lower = path.lower()
            if any(ft in path_lower for ft in FILTERED_CONTENT_TYPES):
                continue

            # 相对路径模块
            if path.startswith('./'):
                self.collected['module_files'].add(path)
                continue

            # 绝对路径API
            if path.startswith('/'):
                if len(path) <= 4 and re.search(r'[A-Z\.\/\#\+\?23]', path[1:]):
                    continue
                self.collected['absolute_apis'].add(path)
            else:
                # 相对路径API
                if self.SKIP_API_PREFIXES.match(path):
                    continue
                if len(path) <= 4:
                    continue
                self.collected['apis'].add(path)

    def _validate_credential(self, text: str) -> bool:
        """验证凭证是否有效"""
        parts = re.split(r'\s*[:=]\s*', text.strip(), maxsplit=1)
        if len(parts) < 2:
            return False

        value_part = parts[1].strip('"\'{}\[\]，：。？、?!><')

        if not value_part:
            return False
        if value_part.startswith('/') or value_part.startswith('http'):
            return False
        if re.search(r'[\u4e00-\u9fa5]', value_part):
            return False
        if len(value_part) <= 1:
            return False
        if value_part.lower() in ('true', 'false', 'null', 'undefined', 'none'):
            return False

        key_part = parts[0].strip('"\'').lower()
        if key_part.startswith('coord'):
            return False
        if re.match(r'^\/|^true$|^false$|^register$|^signUp$|^basic$|^http', value_part, re.IGNORECASE):
            return False

        return True

    def _validate_id_key(self, text: str) -> bool:
        """验证ID密钥是否有效"""
        if not text:
            return False

        has_separator = ':' in text or '=' in text

        if has_separator:
            parts = re.split(r'\s*[:=]\s*', text.replace(' ', ''), maxsplit=1)
            if len(parts) < 2:
                return False

            key_part = parts[0].strip('"\'<>')
            value_part = parts[1].strip('"\'<>')

            key_lower = key_part.lower()
            value_lower = value_part.lower()

            if not value_part:
                return False
            if key_lower == value_lower:
                return False
            if key_lower in KEY_BLACKLIST:
                return False

            if len(value_part) < 16:
                if value_lower in SHORT_VALUES:
                    return False
                if value_lower in MEDIUM_VALUES:
                    return False
                if re.match(r'^[a-zA-Z]+$', value_part) and len(value_part) < 10:
                    return False
            else:
                if value_lower in MEDIUM_VALUES:
                    return False
                if value_lower in LONG_VALUES:
                    return False

            if key_lower == 'key' and len(value_part) <= 8:
                return False
            if key_lower == 'key' and self.CAMEL_CASE_PATTERN.search(value_part):
                return False

            if len(value_part) <= 3:
                return False

            return True
        else:
            text_stripped = text.strip('"\'')
            if re.match(r'^[a-zA-Z]+$', text_stripped):
                return False

            text_lower = text_stripped.lower()
            for mv in MEDIUM_VALUES:
                if mv in text_lower:
                    return False
            for lv in LONG_VALUES:
                if lv in text_lower:
                    return False

            return True

    def get_summary(self) -> Dict:
        """获取汇总结果"""
        return {
            'domains': list(self.collected['domains']),
            'routes': list(self.collected['routes']),
            'absolute_apis': list(self.collected['absolute_apis']),
            'apis': list(self.collected['apis']),
            'module_files': list(self.collected['module_files']),
            'doc_files': list(self.collected['doc_files']),
            'ips': list(self.collected['ips']),
            'phones': list(self.collected['phones']),
            'emails': list(self.collected['emails']),
            'idcards': list(self.collected['idcards']),
            'jwts': list(self.collected['jwts']),
            'image_files': list(self.collected['image_files']),
            'js_files': list(self.collected['js_files']),
            'vue_files': list(self.collected['vue_files']),
            'urls': list(self.collected['urls']),
            'github_urls': list(self.collected['github_urls']),
            'companies': list(self.collected['companies']),
            'credentials': self.collected['credentials'],
            'cookies': self.collected['cookies'],
            'id_keys': self.collected['id_keys'],
        }

    def get_stats(self) -> Dict:
        """获取统计信息"""
        summary = self.get_summary()
        return {k: len(v) for k, v in summary.items()}

    def get_total(self) -> int:
        """获取总数"""
        return sum(self.get_stats().values())

    def reset(self):
        """重置搜集结果"""
        for key in self.collected:
            if isinstance(self.collected[key], set):
                self.collected[key].clear()
            elif isinstance(self.collected[key], list):
                self.collected[key].clear()
