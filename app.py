#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JSLeakHunter v2.1 - Enhanced Backend
Fixed: Unicode surrogates not allowed
Enhanced: Information collection (domains, IPs, phones, emails, credentials, etc.)
Enhanced: Webpack chunk JS extraction
"""

import csv
import json
import os
import sqlite3
import sys
import io
import threading
import uuid
from datetime import datetime
from io import StringIO

# ============ Windows编码修复 (必须在最前面) ============
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    os.environ['PYTHONUTF8'] = '1'
    
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='ignore')
            sys.stderr.reconfigure(encoding='utf-8', errors='ignore')
        else:
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, 
                encoding='utf-8', 
                errors='ignore'
            )
            sys.stderr = io.TextIOWrapper(
                sys.stderr.buffer, 
                encoding='utf-8', 
                errors='ignore'
            )
    except Exception:
        pass

import requests
from flask import Flask, render_template, request, Response, jsonify


# ============ 安全导入模块 ============
try:
    from scanner import Scanner
except ImportError as e:
    print(f"[!] Warning: scanner module not found: {e}")
    Scanner = None

try:
    from analyzer import AIAnalyzer
except ImportError as e:
    print(f"[!] Warning: analyzer module not found: {e}")
    AIAnalyzer = None

try:
    from js_extractor import extract_js_files
except ImportError as e:
    print(f"[!] Warning: js_extractor module not found: {e}")
    extract_js_files = None

try:
    from patterns import get_patterns
except ImportError as e:
    print(f"[!] Warning: patterns module not found: {e}")
    def get_patterns():
        return {}

try:
    from info_collector import InfoCollector
except ImportError as e:
    print(f"[!] Warning: info_collector module not found: {e}")
    InfoCollector = None


# ================================================================
# Unicode清理函数
# ================================================================

def clean_surrogates(text):
    """清理无效的Unicode代理对字符"""
    if not isinstance(text, str):
        return text
    try:
        return text.encode('utf-8', errors='ignore').decode('utf-8')
    except Exception:
        return ''.join(c for c in text if ord(c) < 0xD800 or ord(c) > 0xDFFF)


def clean_data(data):
    """递归清理数据结构中的所有字符串"""
    if isinstance(data, str):
        return clean_surrogates(data)
    elif isinstance(data, dict):
        return {clean_surrogates(k) if isinstance(k, str) else k: clean_data(v) for k, v in data.items()}
    elif isinstance(data, (list, tuple)):
        return [clean_data(item) for item in data]
    elif isinstance(data, bytes):
        try:
            return data.decode('utf-8', errors='ignore')
        except Exception:
            return str(data)
    return data


def safe_json_dumps(obj, ensure_ascii=False, default=str, **kwargs):
    """安全的JSON序列化"""
    cleaned = clean_data(obj)
    return json.dumps(cleaned, ensure_ascii=ensure_ascii, default=default, **kwargs)


def safe_str(text, max_len=1000):
    """安全转换为字符串"""
    if text is None:
        return ''
    result = clean_surrogates(str(text))
    if max_len and len(result) > max_len:
        result = result[:max_len] + '...'
    return result


# ================================================================
# Flask App
# ================================================================

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'scans.db')
active_scans = {}
db_lock = threading.Lock()

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    """Initialize database"""
    try:
        conn = get_db_connection()
        conn.execute('''CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            started_at TEXT,
            completed_at TEXT,
            total_files INTEGER DEFAULT 0,
            findings_json TEXT DEFAULT '[]',
            stats_json TEXT DEFAULT '{}',
            config_json TEXT DEFAULT '{}',
            info_json TEXT DEFAULT '{}'
        )''')
        conn.commit()
        conn.close()
        
        # Add info_json column if it doesn't exist (migration)
        try:
            conn = get_db_connection()
            conn.execute("SELECT info_json FROM scans LIMIT 1")
            conn.close()
        except sqlite3.OperationalError:
            conn = get_db_connection()
            conn.execute("ALTER TABLE scans ADD COLUMN info_json TEXT DEFAULT '{}'")
            conn.commit()
            conn.close()
        
        print("[+] Database initialized")
    except Exception as e:
        print(f"[!] Database init error: {e}")


init_db()


# ================================================================
# Routes
# ================================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target URL is required'}), 400

    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    targets = [t.strip() for t in target.split(',') if t.strip()]

    scan_id = str(uuid.uuid4())[:8]
    config = {
        'target': targets[0] if len(targets) == 1 else targets,
        'targets': targets,
        'api_url': data.get('api_url', 'https://token-plan-cn.xiaomimimo.com/v1').strip(),
        'api_key': data.get('api_key', '').strip(),
        'model': data.get('model', 'mimo-v2.5-pro').strip(),
        'depth': int(data.get('depth', 2)),
        'cookie': data.get('cookie', '').strip(),
        'skip_ai': not data.get('api_key', '').strip(),
        'use_browser': data.get('use_browser', False),
        'full_scan': data.get('full_scan', False),
    }

    try:
        with db_lock:
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO scans (id, target, status, started_at, config_json) VALUES (?,?,?,?,?)",
                (scan_id, ','.join(targets), 'running', datetime.now().isoformat(), safe_json_dumps(config))
            )
            conn.commit()
            conn.close()
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

    active_scans[scan_id] = {
        'status': 'running',
        'progress': 0,
        'current_file': '',
        'total_files': 0,
        'logs': [],
        'findings': [],
        'stats': {},
        'info': {},  # NEW: Information collection results
    }

    thread = threading.Thread(target=run_scan_thread, args=(scan_id, config), daemon=True)
    thread.start()

    return jsonify({'scan_id': scan_id, 'targets': len(targets)})


def run_scan_thread(scan_id, config):
    """Run scan in background thread"""
    scan_state = active_scans[scan_id]

    def log_callback(msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        scan_state['logs'].append(f"[{timestamp}] {safe_str(msg)}")

    def progress_callback(current, total, filename):
        scan_state['progress'] = int(current / max(total, 1) * 100)
        scan_state['total_files'] = total
        scan_state['current_file'] = safe_str(filename)

    targets = config.get('targets', [config['target']])
    all_findings = []
    all_info = {}

    for target in targets:
        log_callback(f"[*] Scanning: {target}")
        config_copy = dict(config)
        config_copy['target'] = target

        try:
            if Scanner:
                scanner = Scanner(config_copy, on_log=log_callback)
                findings = scanner.run(progress_callback=progress_callback)
                all_findings.extend(clean_data(findings))
                scan_state['stats'] = scanner.get_stats()
                # NEW: Collect info results
                info_results = scanner.get_info_results()
                if info_results:
                    for key, value in info_results.items():
                        if key not in all_info:
                            all_info[key] = []
                        if isinstance(value, list):
                            all_info[key].extend(value)
                        else:
                            all_info[key].append(value)
            else:
                log_callback("[!] Scanner module not available")
        except Exception as e:
            log_callback(f"[!] Error: {safe_str(str(e), 200)}")

    scan_state['findings'] = all_findings
    scan_state['info'] = all_info
    scan_state['status'] = 'completed'
    scan_state['progress'] = 100

    try:
        with db_lock:
            conn = get_db_connection()
            conn.execute(
                "UPDATE scans SET status=?, completed_at=?, findings_json=?, stats_json=?, info_json=? WHERE id=?",
                (
                    'completed',
                    datetime.now().isoformat(),
                    safe_json_dumps(all_findings),
                    safe_json_dumps(scan_state.get('stats', {})),
                    safe_json_dumps(all_info),
                    scan_id
                )
            )
            conn.commit()
            conn.close()
    except Exception as e:
        log_callback(f"[!] DB Error: {safe_str(str(e), 100)}")


# ================================================================
# Extract JS Files Endpoint
# ================================================================

@app.route('/api/extract', methods=['POST'])
def extract_js_only():
    """Extract JS files only (for preview)"""
    data = request.json or {}
    target = data.get('target', '').strip()

    if not target:
        return jsonify({'error': 'Target URL is required'}), 400

    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        cookie = data.get('cookie', '').strip()
        if cookie:
            headers['Cookie'] = cookie

        resp = requests.get(target, headers=headers, timeout=15, verify=False)
        resp.raise_for_status()

        if extract_js_files:
            js_info, stats = extract_js_files(
                html_content=resp.text,
                page_url=target,
                headers=headers,
                use_browser=data.get('use_browser', False),
                depth=int(data.get('depth', 2)),
                cookie=cookie,
                on_log=None
            )
        else:
            # Fallback: basic JS extraction
            import re
            js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp.text)
            js_info = [{'url': u, 'type': 'external'} for u in js_urls]
            stats = {'total': len(js_info)}

        return jsonify({
            'success': True,
            'target': target,
            'total': len(js_info),
            'js_files': clean_data(js_info),
            'stats': clean_data(stats)
        })

    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request timeout'}), 504
    except Exception as e:
        return jsonify({'error': safe_str(str(e))}), 500


@app.route('/api/scan-selected', methods=['POST'])
def scan_selected_js():
    """Scan selected JS files"""
    data = request.json or {}
    js_urls = data.get('js_urls', [])

    if not js_urls:
        return jsonify({'error': 'No JS files selected'}), 400

    scan_id = str(uuid.uuid4())[:8]
    config = {
        'js_urls': js_urls,
        'api_url': data.get('api_url', '').strip(),
        'api_key': data.get('api_key', '').strip(),
        'model': data.get('model', 'mimo-v2.5-pro').strip(),
        'cookie': data.get('cookie', '').strip(),
        'skip_ai': not data.get('api_key', '').strip(),
        'full_scan': data.get('full_scan', False),
    }

    try:
        with db_lock:
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO scans (id, target, status, started_at, config_json) VALUES (?,?,?,?,?)",
                (scan_id, f"Selected {len(js_urls)} files", 'running', datetime.now().isoformat(), safe_json_dumps(config))
            )
            conn.commit()
            conn.close()
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

    active_scans[scan_id] = {
        'status': 'running',
        'progress': 0,
        'current_file': '',
        'total_files': len(js_urls),
        'logs': [],
        'findings': [],
        'stats': {},
        'info': {},  # NEW
    }

    thread = threading.Thread(target=run_selected_scan_thread, args=(scan_id, config), daemon=True)
    thread.start()

    return jsonify({'scan_id': scan_id, 'total_files': len(js_urls)})


def run_selected_scan_thread(scan_id, config):
    """Scan selected JS files"""
    scan_state = active_scans[scan_id]

    def log_callback(msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        scan_state['logs'].append(f"[{timestamp}] {safe_str(msg)}")

    def progress_callback(current, total, filename):
        scan_state['progress'] = int(current / max(total, 1) * 100)
        scan_state['total_files'] = total
        scan_state['current_file'] = safe_str(filename)

    js_urls = config.get('js_urls', [])
    all_findings = []

    log_callback(f"[*] Scanning {len(js_urls)} selected JS files...")

    patterns = get_patterns()

    temp_config = {
        'target': 'selected_files',
        'api_url': config.get('api_url', ''),
        'api_key': config.get('api_key', ''),
        'model': config.get('model', ''),
        'cookie': config.get('cookie', ''),
        'skip_ai': config.get('skip_ai', True),
    }

    temp_scanner = None
    if Scanner:
        temp_scanner = Scanner(temp_config, on_log=log_callback)

    # NEW: Info collector for selected scan
    info_collector = None
    if InfoCollector:
        info_collector = InfoCollector()

    for idx, url in enumerate(js_urls):
        file_short = safe_str(url.split('/')[-1][:50])
        progress_callback(idx + 1, len(js_urls), file_short)
        log_callback(f"[{idx+1}/{len(js_urls)}] {safe_str(url, 100)}")

        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            if config.get('cookie'):
                headers['Cookie'] = config['cookie']

            resp = requests.get(url, headers=headers, timeout=15, verify=False)
            resp.raise_for_status()
            content = clean_surrogates(resp.text)

            if len(content.strip()) < 30:
                log_callback(f"  -> Skipped (too small)")
                continue

            # Regex precheck
            if temp_scanner:
                regex_results = temp_scanner._regex_precheck(content, url, patterns)
                if regex_results:
                    log_callback(f"  -> Regex: {len(regex_results)} patterns")
                    all_findings.extend(clean_data(regex_results))

            # AI analysis
            if AIAnalyzer and config.get('api_key') and len(content.strip()) > 50:
                log_callback(f"  -> AI analyzing...")
                try:
                    analyzer = AIAnalyzer(
                        config['api_url'],
                        config['api_key'],
                        config['model'],
                        on_log=log_callback
                    )
                    ai_results = analyzer.analyze(content, url, [], full_scan=config.get('full_scan', False))
                    if ai_results:
                        log_callback(f"  -> AI found {len(ai_results)} issues")
                        all_findings.extend(clean_data(ai_results))
                    else:
                        log_callback(f"  -> AI: clean")
                except Exception as e:
                    log_callback(f"  -> AI error: {safe_str(str(e), 50)}")

            # NEW: Information collection
            if info_collector:
                info_collector.collect_all(content, url)

        except Exception as e:
            log_callback(f"  -> Error: {safe_str(str(e), 50)}")

    scan_state['findings'] = all_findings
    scan_state['status'] = 'completed'
    scan_state['progress'] = 100

    # NEW: Store info results
    if info_collector:
        scan_state['info'] = info_collector.get_summary()

    try:
        with db_lock:
            conn = get_db_connection()
            conn.execute(
                "UPDATE scans SET status=?, completed_at=?, findings_json=?, stats_json=?, info_json=? WHERE id=?",
                (
                    'completed',
                    datetime.now().isoformat(),
                    safe_json_dumps(all_findings),
                    safe_json_dumps(scan_state.get('stats', {})),
                    safe_json_dumps(scan_state.get('info', {})),
                    scan_id
                )
            )
            conn.commit()
            conn.close()
    except Exception as e:
        log_callback(f"[!] DB Error: {safe_str(str(e), 50)}")

    log_callback(f"[+] Scan complete: {len(all_findings)} findings")


# ================================================================
# Delete & Batch Delete Endpoints
# ================================================================

@app.route('/api/scan/<scan_id>/delete', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a single scan record"""
    try:
        with db_lock:
            conn = get_db_connection()
            conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
            conn.commit()
            conn.close()
    except Exception:
        pass

    if scan_id in active_scans:
        del active_scans[scan_id]

    return jsonify({'success': True})


@app.route('/api/history/batch-delete', methods=['POST'])
def batch_delete_history():
    """Batch delete scan history"""
    data = request.json or {}
    scan_ids = data.get('scan_ids', [])

    if not scan_ids:
        return jsonify({'error': 'No scan IDs provided'}), 400

    try:
        with db_lock:
            conn = get_db_connection()
            placeholders = ','.join('?' * len(scan_ids))
            conn.execute(f"DELETE FROM scans WHERE id IN ({placeholders})", scan_ids)
            conn.commit()
            conn.close()
    except Exception:
        pass

    for sid in scan_ids:
        if sid in active_scans:
            del active_scans[sid]

    return jsonify({'success': True, 'deleted': len(scan_ids)})


# ================================================================
# SSE Events with Heartbeat
# ================================================================

@app.route('/api/scan/<scan_id>/events')
def scan_events(scan_id):
    import time

    def generate():
        last_log_idx = 0
        last_heartbeat = time.time()

        while True:
            if scan_id not in active_scans:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Scan not found'})}\n\n"
                break

            state = active_scans[scan_id]
            logs = state['logs']

            # Send new logs
            while last_log_idx < len(logs):
                log_msg = clean_surrogates(logs[last_log_idx])
                yield f"data: {json.dumps({'type': 'log', 'message': log_msg})}\n\n"
                last_log_idx += 1
                last_heartbeat = time.time()

            # Send progress
            yield f"data: {json.dumps({'type': 'progress', 'value': state['progress'], 'current': safe_str(state.get('current_file', '')), 'total': state.get('total_files', 0)})}\n\n"
            last_heartbeat = time.time()

            if state['status'] == 'completed':
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                break
            elif state['status'] == 'error':
                yield f"data: {json.dumps({'type': 'error', 'message': 'Scan failed'})}\n\n"
                break

            # Heartbeat every 30s
            if time.time() - last_heartbeat >= 30:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
                last_heartbeat = time.time()

            time.sleep(0.3)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


# ================================================================
# Results & History
# ================================================================

@app.route('/api/scan/<scan_id>/results')
def scan_results(scan_id):
    if scan_id in active_scans:
        state = active_scans[scan_id]
        findings = state['findings']
        info = state.get('info', {})
    else:
        try:
            with db_lock:
                conn = get_db_connection()
                row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
                conn.close()
        except Exception:
            return jsonify({'error': 'Database error'}), 500
            
        if not row:
            return jsonify({'error': 'Not found'}), 404
        findings = json.loads(row[6]) if row[6] else []
        info = json.loads(row[9]) if len(row) > 9 and row[9] else {}
        state = {
            'status': row[2],
            'stats': json.loads(row[7]) if row[7] else {},
        }

    findings = clean_data(findings)
    info = clean_data(info)

    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    med = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
    low = sum(1 for f in findings if f.get('severity') == 'LOW')

    return jsonify({
        'status': state.get('status', 'unknown'),
        'total': len(findings),
        'high': high,
        'medium': med,
        'low': low,
        'findings': findings,
        'stats': state.get('stats', {}),
        'info': info,  # NEW: Information collection results
    })


@app.route('/api/history')
def scan_history():
    try:
        with db_lock:
            conn = get_db_connection()
            rows = conn.execute(
                "SELECT id, target, status, started_at, completed_at, findings_json, info_json FROM scans ORDER BY started_at DESC LIMIT 50"
            ).fetchall()
            conn.close()
    except Exception:
        return jsonify([])

    history = []
    for row in rows:
        findings = json.loads(row[5]) if row[5] else []
        info = json.loads(row[6]) if len(row) > 6 and row[6] else {}
        info_count = sum(len(v) for v in info.values() if isinstance(v, list))
        history.append({
            'id': row[0],
            'target': safe_str(row[1], 100),
            'status': row[2],
            'started_at': row[3],
            'completed_at': row[4],
            'total': len(findings),
            'high': sum(1 for f in findings if f.get('severity') == 'HIGH'),
            'medium': sum(1 for f in findings if f.get('severity') == 'MEDIUM'),
            'low': sum(1 for f in findings if f.get('severity') == 'LOW'),
            'info_count': info_count,  # NEW: Info count
        })

    return jsonify(history)

@app.route('/api/extract/search', methods=['POST'])
def search_js_files():
    """在已提取的JS文件中搜索"""
    data = request.json or {}
    js_files = data.get('js_files', [])
    query = data.get('query', '').strip().lower()
    
    if not query:
        return jsonify({'results': js_files, 'total': len(js_files)})
    
    filtered = [
        f for f in js_files 
        if query in f.get('url', '').lower() or 
           query in f.get('url', '').split('/')[-1].lower()
    ]
    
    return jsonify({
        'results': clean_data(filtered),
        'total': len(filtered),
        'original_total': len(js_files)
    })

@app.route('/api/scan/<scan_id>/export/<fmt>')
def export_report(scan_id, fmt):
    if scan_id in active_scans:
        findings = active_scans[scan_id]['findings']
        target = active_scans[scan_id].get('target', '')
        info = active_scans[scan_id].get('info', {})
    else:
        try:
            with db_lock:
                conn = get_db_connection()
                row = conn.execute("SELECT target, findings_json, info_json FROM scans WHERE id=?", (scan_id,)).fetchone()
                conn.close()
        except Exception:
            return jsonify({'error': 'Database error'}), 500
            
        if not row:
            return jsonify({'error': 'Not found'}), 404
        target = row[0]
        findings = json.loads(row[1]) if row[1] else []
        info = json.loads(row[2]) if len(row) > 2 and row[2] else {}

    findings = clean_data(findings)
    info = clean_data(info)
    target = safe_str(target) if target else ''

    if fmt == 'json':
        return jsonify({
            'target': target,
            'scan_id': scan_id,
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(findings),
            'findings': findings,
            'info': info,  # NEW
        })

    elif fmt == 'csv':
        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(['#', 'Severity', 'Type', 'File', 'Line', 'Evidence', 'Source', 'Recommendation'])
        for i, f in enumerate(findings, 1):
            writer.writerow([
                i,
                safe_str(f.get('severity', '')),
                safe_str(f.get('type', '')),
                safe_str(f.get('url', '')),
                f.get('line', ''),
                safe_str(f.get('evidence', '')),
                safe_str(f.get('source', '')),
                safe_str(f.get('recommendation', ''))
            ])
        
        # NEW: Add info collection to CSV
        if info:
            writer.writerow([])
            writer.writerow(['--- Information Collection ---'])
            for category, items in info.items():
                if isinstance(items, list) and items:
                    writer.writerow([f'=== {category} ({len(items)}) ==='])
                    for item in items:
                        if isinstance(item, dict):
                            writer.writerow([safe_str(item.get('value', '')), safe_str(item.get('name', '')), safe_str(item.get('source', ''))])
                        else:
                            writer.writerow([safe_str(item)])
        
        return Response(si.getvalue(), mimetype='text/csv',
                        headers={'Content-Disposition': f'attachment; filename=jsleakhunter_{scan_id}.csv'})

    elif fmt == 'markdown':
        md = generate_markdown(findings, target, scan_id, info)
        return Response(md, mimetype='text/markdown',
                        headers={'Content-Disposition': f'attachment; filename=jsleakhunter_{scan_id}.md'})

    return jsonify({'error': 'Invalid format. Use json, csv, or markdown'}), 400


def generate_markdown(findings, target, scan_id, info=None):
    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    med = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
    low = sum(1 for f in findings if f.get('severity') == 'LOW')

    md = f"""# JSLeakHunter Scan Report

| Field | Value |
|-------|-------|
| Target | {target} |
| Scan ID | {scan_id} |
| Date | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
| Total Findings | {len(findings)} |

## Summary

| Severity | Count |
|----------|-------|
| HIGH | {high} |
| MEDIUM | {med} |
| LOW | {low} |

## Findings

"""
    for i, f in enumerate(findings, 1):
        evidence = safe_str(f.get('evidence', ''), 200)
        md += f"""### {i}. [{f.get('severity', '?')}] {f.get('type', 'Unknown')}

| Field | Value |
|-------|-------|
| File | `{f.get('url', '')}` |
| Line | {f.get('line', '?')} |
| Source | {f.get('source', '')} |
| Evidence | `{evidence}` |

**Recommendation:** {f.get('recommendation', 'Manual review required')}

---

"""

    # NEW: Information Collection section
    if info:
        md += """## Information Collection

"""
        for category, items in info.items():
            if isinstance(items, list) and items:
                md += f"""### {category} ({len(items)})

"""
                for item in items:
                    if isinstance(item, dict):
                        md += f"- `{safe_str(item.get('value', ''))}`"
                        if item.get('name'):
                            md += f" ({safe_str(item['name'])})"
                        if item.get('source'):
                            md += f" — source: {safe_str(item['source'], 100)}"
                        md += "\n"
                    else:
                        md += f"- `{safe_str(str(item))}`\n"
                md += "\n"

    return md


# ================================================================
# Entry
# ================================================================

if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings()
    
    print("")
    print("=" * 55)
    print("   JSLeakHunter v2.1")
    print("   AI-Powered Frontend Leak Detection")
    print("   Enhanced with Information Collection")
    print("   http://127.0.0.1:5000")
    print("=" * 55)
    print("")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)