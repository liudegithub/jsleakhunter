"""
JSLeakHunter — Detection Patterns v3.3
Based on 雪瞳 tool's detection logic - COMPREHENSIVE
Only ADD, NEVER remove patterns
Enhanced: More detection patterns for tokens, secrets, crypto keys
Enhanced: Additional cloud provider and service patterns
"""

import re

# ============================================================
# Whitelist
# ============================================================
WHITELIST = [
    'your_key_here', 'your_secret_here', 'xxxxxxxxxxxxxxxx',
    '0000000000000000', 'example', 'test123', 'changeme', 'placeholder',
    'dummy', 'sample', 'demo', 'xxx', 'abc123', '123456',
]

WHITELIST_PREFIXES = ['data:image']

# ============================================================
# Flexible separator for compressed code
# ============================================================
SEP = r'\s*[:=]\s*'

# ============================================================
# Short values that are NEVER secrets (from 雪瞳)
# ============================================================
SHORT_VALUES = {
    'up', 'in', 'by', 'of', 'is', 'on', 'to', 'no', 'age', 'all', 'app',
    'ang', 'bar', 'bea', 'big', 'bug', 'can', 'com', 'con', 'cry', 'dom',
    'dow', 'emp', 'ent', 'eta', 'eye', 'for', 'get', 'gen', 'has', 'hei',
    'hid', 'ing', 'int', 'ken', 'key', 'lea', 'log', 'low', 'met', 'mod',
    'new', 'nor', 'not', 'num', 'red', 'obj', 'old', 'out', 'pic', 'pre',
    'pro', 'pop', 'pun', 'put', 'rad', 'ran', 'ref', 'reg', 'ren', 'rig',
    'row', 'sea', 'set', 'seq', 'shi', 'str', 'sub', 'sup', 'sun', 'tab',
    'tan', 'tip', 'top', 'uri', 'url', 'use', 'ver', 'via', 'rce', 'sum',
    'bit', 'kit', 'uid',
    'var', 'let', 'const', 'true', 'false', 'null', 'void', 'this', 'self',
    'page', 'type', 'mode', 'size', 'time', 'date', 'path', 'view',
}

# ============================================================
# Medium values that are NEVER secrets (from 雪瞳)
# ============================================================
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

# ============================================================
# Long values that are NEVER secrets (from 雪瞳)
# ============================================================
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

# ============================================================
# Chinese blacklist - these words indicate non-secret context (from 雪瞳)
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
# Key blacklist - these keywords are NOT actually secrets (from 雪瞳)
# ============================================================
KEY_BLACKLIST = {
    'size', 'row', 'dict', 'up', 'highlight', 'cabin', 'cross', 'time',
}

# ============================================================
# Framework Internal Patterns (for false positive filtering)
# ============================================================
FRAMEWORK_INTERNAL_PATTERNS = [
    r'e\.key\s*=\s*t\.key',
    r'e\.isStatic\s*=\s*t\.isStatic',
    r'e\.isComment\s*=\s*t\.isComment',
    r'e\.fnContext\s*=\s*t\.fnContext',
    r'e\.ns\s*=\s*t\.ns',
    r'tag.*?key.*?isComment',
    r'__webpack_require__',
    r'webpackJsonp',
    r'module\.exports',
    r'Vue\.component',
    r'Vuex\.Store',
    r'VueRouter',
    r'__vue__',
    r'_isVue',
    r'\$createElement',
    r'_self\.\$',
    r'_c\s*=\s*t\.\$createElement',
    r'render\s*:\s*function\s*\(\s*h\s*\)',
    r'render\s*:\s*\(\s*h\s*\)\s*=>',
    r'__esModule',
    r'Object\.defineProperty.*exports',
    r'exports\.default',
    r'n\.exports\s*=',
    r'#__PURE__',
    r'__webpack_public_path__',
    r'chunkLoadingGlobal',
]

# ============================================================
# Credential Detection Keywords (from 雪瞳)
# ============================================================
CREDENTIAL_KEYWORDS = [
    'pwd', 'pass', 'user', 'member', 'account', 'password', 'passwd',
    'admin', 'root', 'system', 'login', 'auth', 'client_secret',
    'client_id', 'oauth', 'bearer', 'jwt',
]

SECRET_KEYWORDS = [
    'secret', 'key', 'token', 'credential', 'auth', 'bearer', 'jwt',
    'apikey', 'api_key', 'access_key', 'private_key', 'encryption_key',
    'signing_key', 'hmac_key', 'master_key', 'mapKey', 'map_key',
]

# ============================================================
# Credential Detection Patterns (from 雪瞳 - 3 modes)
# ============================================================
CREDENTIAL_PATTERNS = [
    {
        'name': 'credential_mode1',
        'pattern': r'''['"]\w*(?:pwd|pass|user|member|account|password|passwd|admin|root|system)[_-]?(?:id|name)?[0-9]*["']\s*[:=]\s*(?:['"][^\,\s\"\(]*["'])''',
        'flags': re.IGNORECASE,
    },
    {
        'name': 'credential_mode2',
        'pattern': r'''\w*(?:pwd|pass|user|member|account|password|passwd|admin|root|system)[_-]?(?:id|name)?[0-9]*\s*[:=]\s*(?:['"][^\,\s\"\(]*["'])''',
        'flags': re.IGNORECASE,
    },
    {
        'name': 'credential_mode3',
        'pattern': r'''['"]\w*(?:pwd|pass|user|member|account|password|passwd|admin|root|system)[_-]?(?:id|name)?[0-9]*\s*[:=]\s*(?:[^\,\s\"\(]*)["']''',
        'flags': re.IGNORECASE,
    },
]

# ============================================================
# Patterns - Comprehensive coverage
# ============================================================
PATTERNS = [
    # ========================================================
    # 1. AWS
    # ========================================================
    {'pattern': r'AKIA[0-9A-Z]{16}', 'label': 'AWS Access Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'aws'},
    {'pattern': r'(?:A3T[A-Z0-9]|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', 'label': 'AWS Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'aws'},
    {'pattern': r'aws[_\-]?(?:secret|access)[_\-]?(?:key|token|id)' + SEP + r'[\'"]?([A-Za-z0-9/+=]{20,})[\'"]?', 'label': 'AWS Credential', 'severity': 'HIGH', 'confidence': 0.90, 'category': 'aws'},
    
    # ========================================================
    # 2. Google/Firebase
    # ========================================================
    {'pattern': r'AIza[0-9A-Za-z_-]{35}', 'label': 'Google API Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'google'},
    {'pattern': r'firebase[_\-]?(?:api[_\-]?)?(?:key|config|secret)' + SEP + r'[\'"]?([^\'"\s]{20,})[\'"]?', 'label': 'Firebase Config', 'severity': 'HIGH', 'confidence': 0.90, 'category': 'google'},
    
    # ========================================================
    # 3. Stripe
    # ========================================================
    {'pattern': r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{20,}', 'label': 'Stripe Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'stripe'},
    
    # ========================================================
    # 4. GitHub
    # ========================================================
    {'pattern': r'gh[ps]_[A-Za-z0-9_]{36,}', 'label': 'GitHub Token', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'github'},
    {'pattern': r'github_pat_[a-zA-Z0-9_]{36,255}', 'label': 'GitHub PAT', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'github'},
    
    # ========================================================
    # 5. Slack
    # ========================================================
    {'pattern': r'xox[bprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', 'label': 'Slack Token', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'slack'},
    
    # ========================================================
    # 6. Twilio
    # ========================================================
    {'pattern': r'SK[0-9a-fA-F]{32}', 'label': 'Twilio Key', 'severity': 'HIGH', 'confidence': 0.90, 'category': 'twilio'},
    
    # ========================================================
    # 7. SendGrid
    # ========================================================
    {'pattern': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', 'label': 'SendGrid Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'sendgrid'},
    
    # ========================================================
    # 8. Alibaba Cloud
    # ========================================================
    {'pattern': r'LTAI[A-Za-z\d]{12,30}', 'label': 'Alibaba Cloud Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'alibaba'},
    
    # ========================================================
    # 9. Tencent Cloud
    # ========================================================
    {'pattern': r'AKID[A-Za-z\d]{13,40}', 'label': 'Tencent Cloud Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'tencent'},
    
    # ========================================================
    # 10. JD Cloud
    # ========================================================
    {'pattern': r'JDC_[0-9A-Z]{25,40}', 'label': 'JD Cloud Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'jd'},
    
    # ========================================================
    # 11. Alipay
    # ========================================================
    {'pattern': r'(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}', 'label': 'Alipay Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'alipay'},
    
    # ========================================================
    # 12. GitLab
    # ========================================================
    {'pattern': r'glpat-[a-zA-Z0-9\-=_]{20,22}', 'label': 'GitLab Token', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'gitlab'},
    
    # ========================================================
    # 13. Apple
    # ========================================================
    {'pattern': r'APID[a-zA-Z0-9]{32,42}', 'label': 'Apple Developer Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'apple'},
    
    # ========================================================
    # 14. WeChat
    # ========================================================
    {'pattern': r'wx[a-z0-9]{15,18}', 'label': 'WeChat Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'wechat'},
    {'pattern': r'ww[a-z0-9]{15,18}', 'label': 'Enterprise WeChat Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'wechat'},
    
    # ========================================================
    # 15. JWT Tokens
    # ========================================================
    {'pattern': r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'label': 'JWT Token', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'token'},
    
    # ========================================================
    # 16. Private Keys & Certificates
    # ========================================================
    {'pattern': r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----', 'label': 'Private Key', 'severity': 'HIGH', 'confidence': 0.99, 'category': 'crypto'},
    {'pattern': r'-----BEGIN\s+CERTIFICATE-----', 'label': 'Certificate', 'severity': 'MEDIUM', 'confidence': 0.90, 'category': 'crypto'},
    
    # ========================================================
    # 17. Encryption Keys (AES/DES)
    # ========================================================
    {'pattern': r'\.enc\.Utf8\.parse\s*\(\s*[\'"]([^\'"]{8,})[\'"]', 'label': 'CryptoJS Key', 'severity': 'HIGH', 'confidence': 0.90, 'category': 'crypto'},
    {'pattern': r'\.(?:encrypt|decrypt)\s*\([^)]*[\'"]([^\'"]{8,})[\'"]', 'label': 'Encryption Key', 'severity': 'HIGH', 'confidence': 0.75, 'category': 'crypto'},
    {'pattern': r'(?:AES|DES|Blowfish|RC4|ECB|CBC|CTR|GCM)[^}]*?[\'"]([A-Za-z0-9+/]{16,}={0,2})[\'"]', 'label': 'Crypto Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'crypto'},
    
    # ========================================================
    # 18. Map Service Keys
    # ========================================================
    {'pattern': r'(?:mapKey|MapKey|map_key|mapkey|mapApiKey)\s*=\s*[\'"]([A-Za-z0-9\-]{20,})[\'"]', 'label': 'Map API Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'map'},
    {'pattern': r'(?:qqmap|qqMap|amap|aMap|baiduMap|googlemap|googleMap)[_\-]?(?:key|Key|apikey|ApiKey)' + SEP + r'[\'"]?([A-Za-z0-9\-]{20,})[\'"]?', 'label': 'Map Service Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'map'},
    {'pattern': r'qqMapKey\s*=\s*[\'"]([A-Za-z0-9\-]{20,})[\'"]', 'label': 'QQ Map Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'map'},
    
    # ========================================================
    # 19. Database Connections
    # ========================================================
    {'pattern': r'(?:mongodb|mysql|postgres|redis|amqp|rabbitmq|mssql|sqlite|oracle|ftp|smtp|ssh)://[^\s\'"]+:[^\s\'"]+@[^\s\'"]+', 'label': 'Connection String', 'severity': 'HIGH', 'confidence': 0.90, 'category': 'database'},
    
    # ========================================================
    # 20. URL with Credentials
    # ========================================================
    {'pattern': r'https?://[^:]+:[^@]+@', 'label': 'URL with Credentials', 'severity': 'HIGH', 'confidence': 0.90, 'category': 'url'},
    {'pattern': r'(?:api_key|apikey|access_token|auth_token|secret|password|token|key)=([^&\s\'"]{8,})', 'label': 'Secret in URL', 'severity': 'HIGH', 'confidence': 0.80, 'category': 'url'},
    
    # ========================================================
    # 21. Internal Infrastructure
    # ========================================================
    {'pattern': r'(?:https?://|["\'])((?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?)', 'label': 'Internal IP', 'severity': 'MEDIUM', 'confidence': 0.75, 'category': 'infra'},
    
    # ========================================================
    # 22. Generic Token
    # ========================================================
    {'pattern': r'token' + SEP + r'[\'"]?([^\'"\s,;}{\)]{20,})[\'"]?', 'label': 'Token', 'severity': 'HIGH', 'confidence': 0.75, 'category': 'token'},
    
    # ========================================================
    # 23. 雪瞳 key1 - Generic secret/key detection
    # ========================================================
    {
        'pattern': r'''(?:['"]?(?:[\w-]*(?:secret|oss|bucket|key)[\w-]*)|ak["']?)\s*[:=]\s*(?:"(?!\+)[^\,\s\"\(\>\<]{6,}"|'(?!\+)[^\,\s\'\(\>\<]{6,}'|[0-9a-zA-Z_-]{16,})''',
        'label': 'Generic Secret/Key',
        'severity': 'HIGH',
        'confidence': 0.75,
        'category': 'idkey',
    },
    # ========================================================
    # 24. 雪瞳 key2 - 32-char hex string
    # ========================================================
    {
        'pattern': r'''["'][a-zA-Z0-9]{32}["']''',
        'label': '32-char Key/Hash',
        'severity': 'MEDIUM',
        'confidence': 0.60,
        'category': 'idkey',
    },
    # ========================================================
    # 25. Access Token
    # ========================================================
    {'pattern': r'access[_\-]?token' + SEP + r'[\'"]?([A-Za-z0-9_\-\.]{20,})[\'"]?', 'label': 'Access Token', 'severity': 'HIGH', 'confidence': 0.80, 'category': 'token'},
    # ========================================================
    # 26. Refresh Token
    # ========================================================
    {'pattern': r'refresh[_\-]?token' + SEP + r'[\'"]?([A-Za-z0-9_\-\.]{20,})[\'"]?', 'label': 'Refresh Token', 'severity': 'HIGH', 'confidence': 0.80, 'category': 'token'},
    # ========================================================
    # 27. Session Token/ID/Key
    # ========================================================
    {'pattern': r'session[_\-]?(?:token|id|key)' + SEP + r'[\'"]?([A-Za-z0-9_\-\.]{16,})[\'"]?', 'label': 'Session Token', 'severity': 'HIGH', 'confidence': 0.75, 'category': 'token'},
    # ========================================================
    # 28. Authorization Header
    # ========================================================
    {'pattern': r'Authorization["\']\s*:\s*["\'](?:Bearer\s+)?([A-Za-z0-9_\-\.]{20,})["\']', 'label': 'Authorization Header', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'token'},
    # ========================================================
    # 29. Private Key (generic)
    # ========================================================
    {'pattern': r'private[_\-]?key' + SEP + r'[\'"]?([A-Za-z0-9_\-/+=]{20,})[\'"]?', 'label': 'Private Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'crypto'},
    # ========================================================
    # 30. Secret Key (generic)
    # ========================================================
    {'pattern': r'secret[_\-]?key' + SEP + r'[\'"]?([A-Za-z0-9_\-/+=]{16,})[\'"]?', 'label': 'Secret Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'crypto'},
    # ========================================================
    # 31. Encryption Key (generic)
    # ========================================================
    {'pattern': r'encryption[_\-]?key' + SEP + r'[\'"]?([A-Za-z0-9_\-/+=]{16,})[\'"]?', 'label': 'Encryption Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'crypto'},
    # ========================================================
    # 32. Signing Key
    # ========================================================
    {'pattern': r'signing[_\-]?key' + SEP + r'[\'"]?([A-Za-z0-9_\-/+=]{16,})[\'"]?', 'label': 'Signing Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'crypto'},
    # ========================================================
    # 33. HMAC Key
    # ========================================================
    {'pattern': r'hmac[_\-]?key' + SEP + r'[\'"]?([A-Za-z0-9_\-/+=]{16,})[\'"]?', 'label': 'HMAC Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'crypto'},
    # ========================================================
    # 34. Master Key
    # ========================================================
    {'pattern': r'master[_\-]?key' + SEP + r'[\'"]?([A-Za-z0-9_\-/+=]{16,})[\'"]?', 'label': 'Master Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'crypto'},
    # ========================================================
    # 35. App Secret
    # ========================================================
    {'pattern': r'app[_\-]?secret' + SEP + r'[\'"]?([A-Za-z0-9_\-/+=]{16,})[\'"]?', 'label': 'App Secret', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'secret'},
    # ========================================================
    # 36. Consumer Secret
    # ========================================================
    {'pattern': r'consumer[_\-]?secret' + SEP + r'[\'"]?([A-Za-z0-9_\-/+=]{16,})[\'"]?', 'label': 'Consumer Secret', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'secret'},
    # ========================================================
    # 37. 微信小程序密钥
    # ========================================================
    {'pattern': r'wx[a-z0-9]{16,18}', 'label': 'WeChat Mini Program Key', 'severity': 'HIGH', 'confidence': 0.80, 'category': 'wechat'},
    # ========================================================
    # 38. 企业微信密钥
    # ========================================================
    {'pattern': r'ww[a-z0-9]{16,18}', 'label': 'Enterprise WeChat Key', 'severity': 'HIGH', 'confidence': 0.80, 'category': 'wechat'},
    # ========================================================
    # 39. 阿里云AccessKey (补充)
    # ========================================================
    {'pattern': r'LTAI[A-Za-z\d]{12,30}', 'label': 'Alibaba Cloud AccessKey', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'alibaba'},
    # ========================================================
    # 40. 腾讯云SecretKey
    # ========================================================
    {'pattern': r'AKID[A-Za-z\d]{13,40}', 'label': 'Tencent Cloud SecretKey', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'tencent'},
    # ========================================================
    # 41. 京东云密钥
    # ========================================================
    {'pattern': r'JDC_[0-9A-Z]{25,40}', 'label': 'JD Cloud Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'jd'},
    # ========================================================
    # 42. 支付宝密钥
    # ========================================================
    {'pattern': r'(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}', 'label': 'Alipay Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'alipay'},
    # ========================================================
    # 43. Apple开发者密钥
    # ========================================================
    {'pattern': r'APID[a-zA-Z0-9]{32,42}', 'label': 'Apple Developer Key', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'apple'},
    # ========================================================
    # 44. GitLab Token
    # ========================================================
    {'pattern': r'glpat-[a-zA-Z0-9\-=_]{20,22}', 'label': 'GitLab Personal Access Token', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'gitlab'},
    # ========================================================
    # 45. Docker Hub Token
    # ========================================================
    {'pattern': r'dckr_pat_[a-zA-Z0-9_]{20,}', 'label': 'Docker Hub Token', 'severity': 'HIGH', 'confidence': 0.90, 'category': 'docker'},
    # ========================================================
    # 46. NPM Token
    # ========================================================
    {'pattern': r'npm_[a-zA-Z0-9]{36}', 'label': 'NPM Token', 'severity': 'HIGH', 'confidence': 0.90, 'category': 'npm'},
    # ========================================================
    # 47. Slack Webhook
    # ========================================================
    {'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}', 'label': 'Slack Webhook URL', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'slack'},
    # ========================================================
    # 48. Discord Webhook
    # ========================================================
    {'pattern': r'https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_\-]+', 'label': 'Discord Webhook URL', 'severity': 'HIGH', 'confidence': 0.95, 'category': 'discord'},
    # ========================================================
    # 49. 微信AppID
    # ========================================================
    {'pattern': r'(?:appid|app_id|appId)\s*[:=]\s*["\']?(wx[a-z0-9]{16})["\']?', 'label': 'WeChat AppID', 'severity': 'MEDIUM', 'confidence': 0.80, 'category': 'wechat'},
    # ========================================================
    # 50. 高德地图Key
    # ========================================================
    {'pattern': r'(?:amap|aMap|amapkey|amapKey|amap_key)[_\-]?(?:key|Key|apikey|ApiKey)\s*[:=]\s*["\']?([a-f0-9]{32})["\']?', 'label': 'AMap Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'map'},
    # ========================================================
    # 51. 腾讯地图Key
    # ========================================================
    {'pattern': r'(?:qqmap|qqMap|qqmapkey|qqMapKey)[_\-]?(?:key|Key|apikey|ApiKey)\s*[:=]\s*["\']?([A-Za-z0-9\-]{20,})["\']?', 'label': 'QQ Map Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'map'},
    # ========================================================
    # 52. 百度地图Key
    # ========================================================
    {'pattern': r'(?:baidumap|baiduMap|baidu_map)[_\-]?(?:key|Key|apikey|ApiKey)\s*[:=]\s*["\']?([A-Za-z0-9]{20,})["\']?', 'label': 'Baidu Map Key', 'severity': 'HIGH', 'confidence': 0.85, 'category': 'map'},
]


# ============================================================
# Helper Functions
# ============================================================

def is_camel_case(text):
    """Check if text is camelCase (from 雪瞳)"""
    return bool(re.search(r'\b[_a-z]+(?:[A-Z][a-z]+)+\b', text))


def contains_chinese(text):
    """Check if text contains Chinese characters"""
    return bool(re.search(r'[\u4e00-\u9fa5]', text))


def is_short_value(text):
    """Check if value is a common short word that is NOT a secret"""
    if not text:
        return False
    return text.lower().strip() in SHORT_VALUES


def is_medium_value(text):
    """Check if value is a common medium word that is NOT a secret"""
    if not text:
        return False
    return text.lower().strip() in MEDIUM_VALUES


def is_long_value(text):
    """Check if value is a common long word that is NOT a secret"""
    if not text:
        return False
    return text.lower().strip() in LONG_VALUES


def is_key_blacklisted(key_name):
    """Check if a key name is blacklisted (not actually a secret)"""
    if not key_name:
        return False
    return key_name.lower().strip() in KEY_BLACKLIST


def is_id_key_valid(matched_text):
    """
    Validate if a matched text is likely a real ID/key secret.
    Based on 雪瞳's L.id_key filtering logic.
    Returns True if it should be REPORTED, False if it's a false positive.
    """
    if not matched_text:
        return False

    has_separator = ':' in matched_text or '=' in matched_text

    if has_separator:
        parts = re.split(r'\s*[:=]\s*', matched_text.replace(' ', ''), maxsplit=1)
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
        if is_key_blacklisted(key_lower):
            return False

        if len(value_part) < 16:
            if is_short_value(value_lower):
                return False
            if is_medium_value(value_lower):
                return False
            if re.match(r'^[a-zA-Z]+$', value_part) and len(value_part) < 10:
                return False
        else:
            if is_medium_value(value_lower):
                return False
            if is_long_value(value_lower):
                return False

        if key_lower == 'key' and len(value_part) <= 8:
            return False
        if key_lower == 'key' and is_camel_case(value_part):
            return False

        if len(value_part) <= 3:
            return False

        return True
    else:
        text_stripped = matched_text.strip('"\'')
        text_lower = text_stripped.lower()

        if re.match(r'^[a-zA-Z]+$', text_stripped):
            return False

        for mv in MEDIUM_VALUES:
            if mv in text_lower:
                return False
        for lv in LONG_VALUES:
            if lv in text_lower:
                return False

        return True


def is_credential_valid(matched_text):
    """
    Validate if a matched text is likely a real credential.
    Based on 雪瞳's L.credentials filtering logic.
    """
    if not matched_text:
        return False

    parts = re.split(r'\s*[:=]\s*', matched_text.replace(' ', ''), maxsplit=1)
    if len(parts) < 2:
        return False

    key_part = parts[0].strip('"\'').lower()
    value_part = parts[1].strip('"\'{}\[\]，：。？、?!><')

    if not value_part:
        return False

    if key_part.startswith('coord'):
        return False

    value_patterns = [
        r'^/', r'^true$', r'^false$', r'^register$', r'^signUp$',
        r'^basic$', r'^http',
    ]
    for vp in value_patterns:
        if re.match(vp, value_part, re.IGNORECASE):
            return False

    if len(value_part) <= 1:
        return False

    if contains_chinese(value_part):
        return False

    return True


def get_patterns():
    return PATTERNS


def get_whitelist():
    return WHITELIST


def get_whitelist_prefixes():
    return WHITELIST_PREFIXES


def get_credential_keywords():
    return CREDENTIAL_KEYWORDS


def get_secret_keywords():
    return SECRET_KEYWORDS


def get_framework_patterns():
    return FRAMEWORK_INTERNAL_PATTERNS


def get_short_values():
    return SHORT_VALUES


def get_medium_values():
    return MEDIUM_VALUES


def get_long_values():
    return LONG_VALUES


def get_chinese_blacklist():
    return CHINESE_BLACKLIST


def get_key_blacklist():
    return KEY_BLACKLIST


def get_credential_patterns():
    return CREDENTIAL_PATTERNS


def is_whitelisted(text):
    """Check if text is whitelisted"""
    if not text:
        return False
    lower = text.lower().strip()

    for prefix in WHITELIST_PREFIXES:
        if lower.startswith(prefix):
            return True

    for wl in WHITELIST:
        if wl.lower() == lower:
            return True

    placeholders = [
        'your_key_here', 'your_secret_here', 'your_api_key',
        'replace_with', 'insert_here', 'change_me',
        'xxxxxxxx', '00000000', 'example', 'test', 'dummy',
        'sample', 'demo', 'xxx', 'abc123', '123456',
    ]
    for p in placeholders:
        if lower == p or (len(lower) <= 10 and lower.startswith(p)):
            return True

    return False


def is_framework_internal(line):
    """Check if line contains framework internal patterns"""
    for pattern in FRAMEWORK_INTERNAL_PATTERNS:
        if re.search(pattern, line):
            return True
    return False


def is_non_secret_context(line, matched_text):
    """Check if match is in non-secret context"""
    line_lower = line.lower()

    font_indicators = ['@font-face', 'font-family:', 'format("woff")', 'format("truetype")']
    if sum(1 for i in font_indicators if i in line_lower) >= 2:
        return True

    if any(x in line_lower for x in ['background-color:', 'border-radius:', 'margin-top:']):
        if 'function' not in line_lower and 'var ' not in line_lower:
            return True

    return False


def is_likely_resource_data(text, context_line):
    """Check if text is resource data"""
    if not text or len(text) < 2000:
        return False

    text_lower = text.lower()
    resource_indicators = ['woff', 'woff2', 'ttf', 'eot', 'data:font', 'data:image']
    return any(ind in text_lower for ind in resource_indicators)