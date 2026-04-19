#!/usr/bin/env python3
"""
PHANTOM OSINT Framework v3.0
Ultra-powerful open-source intelligence gathering tool
For authorized security research and educational purposes only.
"""

import json, re, socket, ssl, urllib.request, urllib.parse, urllib.error
import hashlib, base64, ipaddress, subprocess, platform, time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import threading

# ═══════════════════════════════════════════════════════════════════════════════
# HELPER
# ═══════════════════════════════════════════════════════════════════════════════

def http_get(url, timeout=10, headers=None):
    req = urllib.request.Request(url)
    req.add_header('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read().decode('utf-8', errors='ignore'), dict(r.headers), r.status

def clean_domain(target):
    return re.sub(r'^https?://', '', target).rstrip('/').split('/')[0]

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — WHOIS
# ═══════════════════════════════════════════════════════════════════════════════

def whois_lookup(target):
    results = {}
    whois_servers = {
        '.com': 'whois.verisign-grs.com', '.net': 'whois.verisign-grs.com',
        '.org': 'whois.pir.org', '.io': 'whois.nic.io', '.fr': 'whois.nic.fr',
        '.de': 'whois.denic.de', '.uk': 'whois.nominet.uk', '.eu': 'whois.eu',
        '.co': 'whois.nic.co', '.app': 'whois.nic.google', '.dev': 'whois.nic.google',
        '.ru': 'whois.tcinet.ru',
    }
    try:
        server = 'whois.iana.org'
        for tld, srv in whois_servers.items():
            if target.endswith(tld):
                server = srv; break
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, 43))
        sock.send(f"{target}\r\n".encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            data += chunk
        sock.close()
        raw = data.decode('utf-8', errors='ignore')
        results['raw'] = raw; results['server'] = server
        fields = {}
        patterns = {
            'Registrar': r'(?:Registrar|registrar):\s*(.+)',
            'Created': r'(?:Creation Date|created|Registered):\s*(.+)',
            'Updated': r'(?:Updated Date|last-modified):\s*(.+)',
            'Expires': r'(?:Expiry Date|Expiration Date|expires):\s*(.+)',
            'Name Servers': r'(?:Name Server|nserver):\s*(.+)',
            'Status': r'(?:Domain Status|status):\s*(.+)',
            'Registrant': r'(?:Registrant Organization|org):\s*(.+)',
            'Country': r'(?:Registrant Country|country):\s*(.+)',
            'DNSSEC': r'(?:DNSSEC|dnssec):\s*(.+)',
        }
        for key, pattern in patterns.items():
            matches = re.findall(pattern, raw, re.IGNORECASE)
            if matches:
                fields[key] = list(dict.fromkeys([m.strip() for m in matches]))[:4]
        results['parsed'] = fields; results['status'] = 'success'
    except Exception as e:
        results['status'] = 'error'; results['error'] = str(e)
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — DNS ENUM
# ═══════════════════════════════════════════════════════════════════════════════

def dns_lookup(target):
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA']
    for rtype in record_types:
        try:
            if platform.system() == 'Windows':
                cmd = ['nslookup', f'-type={rtype}', target]
            else:
                cmd = ['dig', '+short', rtype, target]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            out = proc.stdout.strip()
            if out and not out.startswith(';'):
                lines = [l.strip() for l in out.split('\n') if l.strip()]
                if lines: results[rtype] = lines
        except: pass
    # SPF
    try:
        cmd = ['dig', '+short', 'TXT', target] if platform.system() != 'Windows' else ['nslookup', '-type=TXT', target]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        spf = [l for l in proc.stdout.split('\n') if 'v=spf1' in l.lower()]
        if spf: results['SPF'] = [s.strip() for s in spf]
    except: pass
    # DMARC
    try:
        cmd = ['dig', '+short', 'TXT', f'_dmarc.{target}'] if platform.system() != 'Windows' else ['nslookup', '-type=TXT', f'_dmarc.{target}']
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        dmarc = [l for l in proc.stdout.split('\n') if 'v=dmarc' in l.lower()]
        if dmarc: results['DMARC'] = [d.strip() for d in dmarc]
    except: pass
    if 'A' not in results:
        try: results['A'] = [socket.gethostbyname(target)]
        except: pass
    if 'A' in results:
        try: results['PTR'] = [socket.gethostbyaddr(results['A'][0])[0]]
        except: pass
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — PORT SCAN
# ═══════════════════════════════════════════════════════════════════════════════

def port_scan(target, ports=None):
    if ports is None:
        ports = [21,22,23,25,53,80,110,143,389,443,445,465,587,
                 993,995,1433,1521,3306,3389,5432,5900,6379,
                 8080,8443,8888,9200,27017]
    results = {'open': [], 'closed': [], 'filtered': []}
    try: results['ip'] = socket.gethostbyname(target)
    except: results['ip'] = target
    service_map = {
        21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',
        110:'POP3',143:'IMAP',389:'LDAP',443:'HTTPS',445:'SMB',
        465:'SMTPS',587:'SMTP-Submission',993:'IMAPS',995:'POP3S',
        1433:'MSSQL',1521:'Oracle DB',3306:'MySQL',3389:'RDP',
        5432:'PostgreSQL',5900:'VNC',6379:'Redis',
        8080:'HTTP-Alt',8443:'HTTPS-Alt',8888:'Jupyter/Dev',
        9200:'Elasticsearch',27017:'MongoDB',
    }
    risk_map = {
        21:'high',23:'high',445:'high',5900:'high',9200:'high',27017:'high',
        22:'medium',3306:'medium',5432:'medium',1433:'medium',6379:'medium',3389:'medium',
    }
    def check_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.2)
        try:
            r = sock.connect_ex((results['ip'], port))
            if r == 0:
                banner = ''
                try:
                    sock.settimeout(0.8)
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(128).decode('utf-8', errors='ignore').split('\n')[0][:60]
                except: pass
                results['open'].append({
                    'port': port,
                    'service': service_map.get(port, 'Unknown'),
                    'banner': banner.strip(),
                    'risk': risk_map.get(port, 'low')
                })
            elif r == 111:
                results['filtered'].append(port)
            else:
                results['closed'].append(port)
        except socket.timeout:
            results['filtered'].append(port)
        except: results['closed'].append(port)
        finally: sock.close()
    threads = [threading.Thread(target=check_port, args=(p,)) for p in ports]
    for t in threads: t.start()
    for t in threads: t.join(timeout=3)
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 4 — SSL/TLS ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def ssl_certificate_info(target, port=443):
    results = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_bin = ssock.getpeercert(binary_form=True)
                results['subject'] = dict(x[0] for x in cert.get('subject', []))
                results['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                results['version'] = cert.get('version')
                results['serial'] = cert.get('serialNumber')
                results['not_before'] = cert.get('notBefore')
                results['not_after'] = cert.get('notAfter')
                results['san'] = [s[1] for s in cert.get('subjectAltName', []) if s[0] == 'DNS']
                results['sha256'] = hashlib.sha256(cert_bin).hexdigest()
                results['sha1'] = hashlib.sha1(cert_bin).hexdigest()
                cipher = ssock.cipher()
                results['cipher'] = cipher
                results['protocol'] = ssock.version()
                # Expiry check
                try:
                    from datetime import timezone
                    exp = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                    results['days_until_expiry'] = days
                    results['expiry_status'] = 'expired' if days < 0 else 'critical' if days < 15 else 'warning' if days < 30 else 'ok'
                except: pass
                results['status'] = 'success'
    except Exception as e:
        results['status'] = 'error'; results['error'] = str(e)
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 5 — HTTP HEADERS + CMS DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def http_headers_analysis(target):
    results = {}
    for scheme in ['https', 'http']:
        url = f"{scheme}://{target}"
        try:
            body, headers, status = http_get(url)
            results['status_code'] = status
            results['url'] = url; results['scheme'] = scheme
            results['headers'] = headers
            results['body_size'] = len(body)
            sec_headers = ['Strict-Transport-Security','Content-Security-Policy',
                'X-Frame-Options','X-Content-Type-Options','X-XSS-Protection',
                'Referrer-Policy','Permissions-Policy','X-Powered-By','Server',
                'X-Generator','Via','X-Cache','CF-Ray','X-Drupal-Cache']
            results['security_headers'] = {h: headers.get(h) or headers.get(h.lower()) for h in sec_headers if headers.get(h) or headers.get(h.lower())}
            tech = []
            combined = (headers.get('Server','') + headers.get('server','') + headers.get('X-Powered-By','') + body[:2000]).lower()
            for kw, name in [('nginx','Nginx'),('apache','Apache'),('cloudflare','Cloudflare'),
                ('iis','Microsoft IIS'),('gunicorn','Gunicorn'),('lighttpd','LightTPD'),
                ('caddy','Caddy'),('php','PHP'),('asp.net','ASP.NET'),('django','Django'),
                ('express','Express.js'),('tomcat','Apache Tomcat')]:
                if kw in combined: tech.append(name)
            results['detected_tech'] = list(dict.fromkeys(tech))
            good = ['Strict-Transport-Security','Content-Security-Policy','X-Frame-Options','X-Content-Type-Options','Referrer-Policy']
            score = sum(1 for h in good if results['security_headers'].get(h))
            results['security_score'] = {'score': score, 'max': len(good), 'grade': ['F','D','C','B','A','A+'][score]}
            cms_patterns = {
                'WordPress': r'wp-content|wp-includes|wordpress',
                'Drupal': r'drupal|/sites/default/files',
                'Joomla': r'joomla|/components/com_',
                'Shopify': r'cdn\.shopify\.com|shopify',
                'Wix': r'wixstatic\.com|wix\.com',
                'Ghost': r'ghost\.io|ghost-theme',
                'Magento': r'mage/cookies|magento',
                'Squarespace': r'squarespace',
            }
            results['cms'] = [name for name, pat in cms_patterns.items() if re.search(pat, body[:5000], re.I)]
            results['status_ok'] = True
            break
        except Exception as e:
            results[f'{scheme}_error'] = str(e)
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 6 — IP GEOLOCATION
# ═══════════════════════════════════════════════════════════════════════════════

def ip_geolocation(ip):
    results = {}
    try:
        try: ipaddress.ip_address(ip)
        except: ip = socket.gethostbyname(ip)
        body, _, _ = http_get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
        results = json.loads(body)
        results['queried_ip'] = ip
    except Exception as e:
        results['status'] = 'error'; results['error'] = str(e)
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 7 — SUBDOMAIN ENUM
# ═══════════════════════════════════════════════════════════════════════════════

def subdomain_enum(domain):
    wordlist = [
        'www','mail','ftp','smtp','pop','imap','webmail','admin','administrator',
        'portal','vpn','remote','dev','development','staging','test','beta','demo',
        'api','api2','v1','v2','ws','cdn','media','static','img','images','assets',
        'shop','store','blog','news','support','help','docs','documentation','wiki',
        'forum','community','dashboard','login','auth','sso','oauth','proxy','gateway',
        'db','database','mysql','redis','mongo','elastic','kibana','grafana',
        'jenkins','gitlab','jira','confluence','bitbucket','git','svn','repo',
        'ci','cd','build','mx','mx1','mx2','ns','ns1','ns2','intranet','internal',
        'corp','office','aws','cloud','status','monitor','cpanel','whm','plesk',
        'search','map','app','apps','mobile','m','secure','pay','payment',
        'checkout','backup','old','new','legacy','archive','lab','labs','sandbox',
        'qa','preprod','preview','uat','prod','production',
    ]
    found = []; lock = threading.Lock()
    def check_sub(sub):
        hostname = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(hostname)
            with lock: found.append({'subdomain': hostname, 'ip': ip})
        except: pass
    threads = [threading.Thread(target=check_sub, args=(s,)) for s in wordlist]
    for t in threads: t.start()
    for t in threads: t.join(timeout=2)
    return {'found': found, 'checked': len(wordlist), 'found_count': len(found)}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 8 — EMAIL OSINT
# ═══════════════════════════════════════════════════════════════════════════════

def email_osint(email):
    results = {}
    if '@' not in email: return {'error': 'Format email invalide'}
    user, domain = email.split('@', 1)
    results['username'] = user; results['domain'] = domain
    norm = email.lower().strip()
    results['md5'] = hashlib.md5(norm.encode()).hexdigest()
    results['sha1'] = hashlib.sha1(norm.encode()).hexdigest()
    results['sha256'] = hashlib.sha256(norm.encode()).hexdigest()
    results['gravatar'] = f"https://www.gravatar.com/avatar/{results['md5']}?s=200&d=404"
    try:
        cmd = ['dig', '+short', 'MX', domain] if platform.system() != 'Windows' else ['nslookup', '-type=MX', domain]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        mx = [l.strip() for l in proc.stdout.split('\n') if l.strip() and not l.startswith(';')]
        results['mx_records'] = mx
    except: results['mx_records'] = []
    providers = {
        'gmail.com':'Google Gmail','googlemail.com':'Google Gmail',
        'yahoo.com':'Yahoo Mail','yahoo.fr':'Yahoo Mail',
        'outlook.com':'Microsoft Outlook','hotmail.com':'Microsoft Hotmail',
        'live.com':'Microsoft Live','protonmail.com':'ProtonMail (chiffré)',
        'proton.me':'ProtonMail (chiffré)','tutanota.com':'Tutanota (chiffré)',
        'icloud.com':'Apple iCloud','aol.com':'AOL Mail','zoho.com':'Zoho Mail',
        'yandex.com':'Yandex Mail','mail.ru':'Mail.ru',
    }
    results['email_provider'] = providers.get(domain.lower(), 'Entreprise / Perso')
    disposable = ['mailinator.com','guerrillamail.com','yopmail.com','trashmail.com',
        '10minutemail.com','temp-mail.org','throwaway.email','fakeinbox.com']
    results['is_disposable'] = domain.lower() in disposable
    results['analysis'] = {
        'numeric_suffix': bool(re.search(r'\d+$', user)),
        'common_separator': any(c in user for c in ['.','_','-']),
        'length': len(user), 'has_numbers': bool(re.search(r'\d', user)),
    }
    results['investigation_links'] = {
        'HaveIBeenPwned': f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}",
        'Gravatar Profile': f"https://www.gravatar.com/{results['md5']}",
        'EmailRep': f"https://emailrep.io/{urllib.parse.quote(email)}",
        'Hunter.io': f"https://hunter.io/email-verifier/{urllib.parse.quote(email)}",
        'Epieos': f"https://epieos.com/?q={urllib.parse.quote(email)}&t=email",
    }
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 9 — USERNAME OSINT
# ═══════════════════════════════════════════════════════════════════════════════

def username_osint(username):
    platforms = {
        'GitHub': f'https://github.com/{username}',
        'GitLab': f'https://gitlab.com/{username}',
        'Twitter/X': f'https://twitter.com/{username}',
        'Instagram': f'https://instagram.com/{username}',
        'Reddit': f'https://reddit.com/user/{username}',
        'YouTube': f'https://youtube.com/@{username}',
        'TikTok': f'https://tiktok.com/@{username}',
        'LinkedIn': f'https://linkedin.com/in/{username}',
        'Pinterest': f'https://pinterest.com/{username}',
        'Twitch': f'https://twitch.tv/{username}',
        'Medium': f'https://medium.com/@{username}',
        'HackerNews': f'https://news.ycombinator.com/user?id={username}',
        'Steam': f'https://steamcommunity.com/id/{username}',
        'Keybase': f'https://keybase.io/{username}',
        'DockerHub': f'https://hub.docker.com/u/{username}',
        'NPM': f'https://www.npmjs.com/~{username}',
        'PyPI': f'https://pypi.org/user/{username}/',
        'Flickr': f'https://www.flickr.com/people/{username}',
        'Vimeo': f'https://vimeo.com/{username}',
        'SoundCloud': f'https://soundcloud.com/{username}',
        'Behance': f'https://behance.net/{username}',
        'Dribbble': f'https://dribbble.com/{username}',
        'Replit': f'https://replit.com/@{username}',
        'Kaggle': f'https://kaggle.com/{username}',
        'HuggingFace': f'https://huggingface.co/{username}',
        'GitHubPages': f'https://{username}.github.io',
        'Gravatar': f'https://en.gravatar.com/{username}',
        'DeviantArt': f'https://deviantart.com/{username}',
        'Spotify': f'https://open.spotify.com/user/{username}',
    }
    results = []; lock = threading.Lock()
    def check_platform(name, url):
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (compatible)')
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                with lock: results.append({'platform': name, 'url': url, 'status': 'found', 'code': resp.status})
        except urllib.error.HTTPError as e:
            with lock: results.append({'platform': name, 'url': url, 'status': 'not_found' if e.code == 404 else 'unknown', 'code': e.code})
        except Exception as e:
            with lock: results.append({'platform': name, 'url': url, 'status': 'error', 'error': str(e)[:60]})
    threads = [threading.Thread(target=check_platform, args=(n, u)) for n, u in platforms.items()]
    for t in threads: t.start()
    for t in threads: t.join(timeout=10)
    found = sorted([r for r in results if r['status'] == 'found'], key=lambda x: x['platform'])
    return {'username': username, 'found': found,
            'not_found': [r for r in results if r['status'] == 'not_found'],
            'errors': [r for r in results if r['status'] in ('error','unknown')],
            'found_count': len(found), 'checked_count': len(results)}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 10 — NETWORK ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def network_analysis(target):
    results = {}
    try:
        cmd = ['tracert','-h','15','-w','500',target] if platform.system()=='Windows' else ['traceroute','-m','15','-w','1',target]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        results['traceroute'] = proc.stdout
    except: results['traceroute'] = 'Traceroute indisponible'
    try:
        cmd = ['ping','-n','4',target] if platform.system()=='Windows' else ['ping','-c','4','-W','2',target]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        results['ping'] = proc.stdout; results['reachable'] = proc.returncode == 0
        rtt = re.findall(r'time[=<]([\d.]+)\s*ms', proc.stdout)
        if rtt:
            rtt_f = [float(r) for r in rtt]
            results['rtt_min'] = min(rtt_f); results['rtt_max'] = max(rtt_f)
            results['rtt_avg'] = round(sum(rtt_f)/len(rtt_f), 2)
    except: results['reachable'] = False; results['ping'] = 'Ping indisponible'
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 11 — ROBOTS.TXT & SITEMAP
# ═══════════════════════════════════════════════════════════════════════════════

def robots_sitemap_analysis(target):
    results = {}
    domain = clean_domain(target)
    for scheme in ['https', 'http']:
        try:
            body, _, status = http_get(f"{scheme}://{domain}/robots.txt")
            results['robots_status'] = status
            results['robots_raw'] = body[:3000]
            results['disallowed_paths'] = [d.strip() for d in re.findall(r'Disallow:\s*(.+)', body, re.I) if d.strip() and d.strip() != '/']
            results['allowed_paths'] = [a.strip() for a in re.findall(r'Allow:\s*(.+)', body, re.I) if a.strip()]
            results['sitemaps'] = [s.strip() for s in re.findall(r'Sitemap:\s*(.+)', body, re.I)]
            results['user_agents'] = list(dict.fromkeys([a.strip() for a in re.findall(r'User-agent:\s*(.+)', body, re.I)]))
            sensitive_kw = ['admin','backup','config','secret','private','internal','login','api',
                            'upload','database','install','setup','phpmy','cpanel','wp-admin','.env','console']
            results['interesting_paths'] = [p for p in results['disallowed_paths'] if any(kw in p.lower() for kw in sensitive_kw)]
            break
        except Exception as e: results['robots_error'] = str(e)
    try:
        sitemap_url = (results.get('sitemaps') or [None])[0] or f"https://{domain}/sitemap.xml"
        body, _, _ = http_get(sitemap_url)
        urls = re.findall(r'<loc>(.*?)</loc>', body)
        results['sitemap_url_count'] = len(urls)
        results['sitemap_sample'] = urls[:20]
    except: results['sitemap_url_count'] = 0
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 12 — GOOGLE DORKS GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

def google_dorks(target):
    domain = clean_domain(target)
    raw_dorks = {
        'Fichiers sensibles': [
            f'site:{domain} filetype:pdf',
            f'site:{domain} filetype:xls OR filetype:xlsx',
            f'site:{domain} filetype:doc OR filetype:docx',
            f'site:{domain} filetype:sql',
            f'site:{domain} filetype:log',
            f'site:{domain} filetype:bak OR filetype:backup',
            f'site:{domain} filetype:conf OR filetype:config',
            f'site:{domain} filetype:env',
        ],
        'Pages d\'administration': [
            f'site:{domain} intitle:"index of"',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:dashboard',
            f'site:{domain} inurl:phpinfo',
            f'site:{domain} inurl:wp-admin',
            f'site:{domain} inurl:phpmyadmin',
            f'site:{domain} inurl:setup OR inurl:install',
        ],
        'Données exposées': [
            f'site:{domain} "username" "password" filetype:txt',
            f'site:{domain} "api_key" OR "api key"',
            f'site:{domain} ext:php inurl:?',
            f'site:{domain} intext:"sql syntax"',
        ],
        'Sous-domaines & infra': [
            f'site:*.{domain}',
            f'site:{domain} -www',
            f'link:{domain}',
            f'related:{domain}',
        ],
        'Mentions publiques': [
            f'"{domain}" site:pastebin.com',
            f'"{domain}" site:github.com',
            f'"{domain}" site:gitlab.com',
        ],
    }
    dorks = {}
    for category, queries in raw_dorks.items():
        dorks[category] = [{'query': q, 'url': f"https://www.google.com/search?q={urllib.parse.quote(q)}"} for q in queries]
    return {'domain': domain, 'dorks': dorks, 'total': sum(len(v) for v in dorks.values())}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 13 — THREAT INTELLIGENCE (Public Sources)
# ═══════════════════════════════════════════════════════════════════════════════

def threat_intelligence(target):
    results = {'target': target}
    try:
        try: ipaddress.ip_address(target); ip = target
        except: ip = socket.gethostbyname(target); results['resolved_ip'] = ip
    except: ip = target
    results['ip'] = ip
    # ThreatCrowd (public, no key)
    try:
        body, _, _ = http_get(f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip}", timeout=8)
        data = json.loads(body)
        results['threatcrowd'] = {
            'votes': data.get('votes', 0),
            'resolutions': data.get('resolutions', [])[:5],
            'hashes': data.get('hashes', [])[:5],
        }
    except: pass
    # HackerTarget ASN
    try:
        body, _, _ = http_get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=8)
        results['asn_info'] = body.strip()
    except: pass
    # HackerTarget reverse DNS
    try:
        body, _, _ = http_get(f"https://api.hackertarget.com/reversedns/?q={ip}", timeout=8)
        results['reverse_dns'] = body.strip()[:500]
    except: pass
    # Investigation links (public, no key required)
    results['investigation_links'] = [
        {'source': 'VirusTotal', 'url': f"https://www.virustotal.com/gui/ip-address/{ip}"},
        {'source': 'Shodan', 'url': f"https://www.shodan.io/host/{ip}"},
        {'source': 'GreyNoise', 'url': f"https://viz.greynoise.io/ip/{ip}"},
        {'source': 'AbuseIPDB', 'url': f"https://www.abuseipdb.com/check/{ip}"},
        {'source': 'Censys', 'url': f"https://search.censys.io/hosts/{ip}"},
        {'source': 'BGPView', 'url': f"https://bgpview.io/ip/{ip}"},
    ]
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 14 — PAGE METADATA EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

def metadata_extractor(target):
    results = {'target': target}
    url = target if target.startswith('http') else f"https://{target}"
    try:
        body, headers, status = http_get(url)
        results['status_code'] = status
        results['content_type'] = headers.get('Content-Type', headers.get('content-type', ''))
        results['last_modified'] = headers.get('Last-Modified', headers.get('last-modified', ''))
        # Meta tags
        meta_tags = {}
        for m in re.finditer(r'<meta\s+([^>]+)>', body, re.I):
            attrs = m.group(1)
            name = re.search(r'(?:name|property)=["\']([^"\']+)["\']', attrs, re.I)
            content = re.search(r'content=["\']([^"\']*)["\']', attrs, re.I)
            if name and content: meta_tags[name.group(1).lower()] = content.group(1)[:200]
        results['meta_tags'] = meta_tags
        results['og'] = {k.replace('og:',''): v for k, v in meta_tags.items() if k.startswith('og:')}
        title = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
        results['title'] = title.group(1).strip()[:200] if title else ''
        results['description'] = meta_tags.get('description', '')
        results['generator'] = meta_tags.get('generator', '')
        # Emails in page
        emails = list(dict.fromkeys(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)))
        results['emails_found'] = [e for e in emails if not any(e.endswith(x) for x in ['.png','.jpg','.gif','.js','.css'])][:20]
        # Phone numbers
        phones = re.findall(r'(?:\+\d{1,3}[\s-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}', body)
        results['phones_found'] = list(dict.fromkeys([p.strip() for p in phones if len(p.strip()) >= 8]))[:10]
        # External links
        all_links = re.findall(r'href=["\']([^"\']+)["\']', body, re.I)
        external = [l for l in all_links if l.startswith('http') and clean_domain(url) not in l]
        results['external_domains'] = list(dict.fromkeys([clean_domain(l) for l in external if l.startswith('http')]))[:20]
        # Social links
        socials = {}
        for name, pat in [('Facebook',r'facebook\.com/[\w.-]+'),('Twitter',r'twitter\.com/[\w.-]+'),
            ('LinkedIn',r'linkedin\.com/[\w/.-]+'),('Instagram',r'instagram\.com/[\w.-]+'),
            ('YouTube',r'youtube\.com/[\w/@.-]+'),('GitHub',r'github\.com/[\w.-]+')]:
            m = re.findall(pat, body, re.I)
            if m: socials[name] = list(dict.fromkeys(['https://' + x for x in m]))[:2]
        results['social_links'] = socials
        # Tracking / Analytics
        tracking = []
        if re.search(r'google-analytics|gtag\(|ga\(', body): tracking.append('Google Analytics')
        if 'googletagmanager.com' in body: tracking.append('Google Tag Manager')
        if 'facebook.net/en_US/fbevents' in body: tracking.append('Facebook Pixel')
        if 'hotjar.com' in body: tracking.append('Hotjar')
        if 'segment.com' in body or 'segment.io' in body: tracking.append('Segment')
        if 'mixpanel.com' in body: tracking.append('Mixpanel')
        if 'plausible.io' in body: tracking.append('Plausible Analytics')
        if 'matomo' in body or 'piwik' in body: tracking.append('Matomo/Piwik')
        results['tracking_detected'] = tracking
        # JS files
        js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
        results['js_files'] = list(dict.fromkeys(js_files[:20]))
    except Exception as e:
        results['error'] = str(e)
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 15 — HASH ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

def hash_analyzer(value):
    value = value.strip()
    results = {'input': value, 'length': len(value)}
    patterns = [
        (r'^[a-fA-F0-9]{32}$', 'MD5'),
        (r'^[a-fA-F0-9]{40}$', 'SHA-1'),
        (r'^[a-fA-F0-9]{64}$', 'SHA-256 / Keccak-256'),
        (r'^[a-fA-F0-9]{96}$', 'SHA-384'),
        (r'^[a-fA-F0-9]{128}$', 'SHA-512'),
        (r'^\$2[ayb]\$.{56}$', 'bcrypt'),
        (r'^\$1\$.+\$.+$', 'MD5-Crypt'),
        (r'^\$6\$.+\$.+$', 'SHA-512-Crypt'),
        (r'^\$argon2', 'Argon2'),
        (r'^[a-fA-F0-9]{8}$', 'CRC32'),
    ]
    hash_types = [name for pat, name in patterns if re.match(pat, value)]
    results['identified_types'] = hash_types if hash_types else ['Inconnu / Texte brut']
    if len(value) < 200 and not re.match(r'^[a-fA-F0-9]{32,}$', value):
        results['hashes_generated'] = {
            'MD5': hashlib.md5(value.encode()).hexdigest(),
            'SHA-1': hashlib.sha1(value.encode()).hexdigest(),
            'SHA-256': hashlib.sha256(value.encode()).hexdigest(),
            'SHA-512': hashlib.sha512(value.encode()).hexdigest(),
            'SHA-384': hashlib.sha384(value.encode()).hexdigest(),
        }
        results['base64_encoded'] = base64.b64encode(value.encode()).decode()
    try:
        decoded = base64.b64decode(value + '==').decode('utf-8', errors='replace')
        if all(c.isprintable() for c in decoded[:50]) and len(decoded) > 2:
            results['base64_decoded'] = decoded[:200]
    except: pass
    results['lookup_links'] = {
        'CrackStation': 'https://crackstation.net/',
        'MD5Decrypt': 'https://md5decrypt.net/en/',
        'HashKiller': 'https://hashkiller.io/listmanager',
    }
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 16 — WAYBACK / DOMAIN TIMELINE
# ═══════════════════════════════════════════════════════════════════════════════

def domain_timeline(domain):
    results = {'domain': domain}
    domain = clean_domain(domain)
    try:
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=8&fl=timestamp,statuscode&collapse=timestamp:6"
        body, _, _ = http_get(cdx_url, timeout=15)
        data = json.loads(body)
        if len(data) > 1:
            snapshots = []
            for row in data[1:]:
                ts = row[0]
                dt = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
                snapshots.append({'date': dt, 'status': row[1]})
            results['wayback_snapshots'] = snapshots
            results['first_seen'] = snapshots[-1]['date'] if snapshots else ''
            results['last_seen'] = snapshots[0]['date'] if snapshots else ''
    except Exception as e: results['wayback_error'] = str(e)
    results['wayback_url'] = f"https://web.archive.org/web/*/{domain}"
    try:
        body, _, _ = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        if 'error' not in body.lower():
            results['historical_hosts'] = [l.strip() for l in body.split('\n') if l.strip()][:20]
    except: pass
    try:
        body, _, _ = http_get(f"https://api.hackertarget.com/findshareddns/?q={domain}", timeout=10)
        if 'error' not in body.lower():
            results['shared_dns_domains'] = [l.strip() for l in body.split('\n') if l.strip()][:15]
    except: pass
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 17 — ASN LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

def asn_lookup(target):
    results = {}
    try:
        try: ipaddress.ip_address(target); ip = target
        except: ip = socket.gethostbyname(target); results['resolved'] = ip
    except: ip = target
    results['ip'] = ip
    try:
        body, _, _ = http_get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=10)
        parts = body.strip().split(',')
        if len(parts) >= 2:
            results['asn'] = parts[0].strip().strip('"')
            results['asn_name'] = parts[1].strip().strip('"')
            results['bgp_prefix'] = parts[2].strip().strip('"') if len(parts) > 2 else ''
            results['country'] = parts[3].strip().strip('"') if len(parts) > 3 else ''
    except Exception as e: results['asn_error'] = str(e)
    results['links'] = {
        'BGPView': f"https://bgpview.io/ip/{ip}",
        'RIPE': f"https://apps.db.ripe.net/db-web-ui/query?searchtext={ip}",
        'ARIN': f"https://search.arin.net/rdap/?query={ip}",
        'Shodan': f"https://www.shodan.io/host/{ip}",
    }
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 18 — FULL RECON
# ═══════════════════════════════════════════════════════════════════════════════

def full_recon(target):
    domain = clean_domain(target)
    result = {}
    result['whois'] = whois_lookup(domain)
    result['dns'] = dns_lookup(domain)
    result['ports'] = port_scan(domain)
    result['ssl'] = ssl_certificate_info(domain)
    result['headers'] = http_headers_analysis(domain)
    result['subdomains'] = subdomain_enum(domain)
    result['robots'] = robots_sitemap_analysis(domain)
    result['metadata'] = metadata_extractor(domain)
    result['timeline'] = domain_timeline(domain)
    if result['dns'].get('A'):
        ip = result['dns']['A'][0]
        result['geo'] = ip_geolocation(ip)
        result['threat'] = threat_intelligence(ip)
        result['asn'] = asn_lookup(ip)
    return result

# ═══════════════════════════════════════════════════════════════════════════════
# WEB SERVER
# ═══════════════════════════════════════════════════════════════════════════════

HTML_CONTENT = (Path(__file__).parent / 'index.html').read_text(encoding='utf-8')

class OSINTHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/':
            body = HTML_CONTENT.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body)
        except:
            self.send_json({'error': 'JSON invalide'}, 400); return
        path = self.path
        target = data.get('target', '').strip()
        if not target:
            self.send_json({'error': 'Cible non spécifiée'}, 400); return
        start = time.time()
        try:
            routes = {
                '/api/whois': lambda: whois_lookup(target),
                '/api/dns': lambda: dns_lookup(target),
                '/api/ports': lambda: port_scan(target, [int(p.strip()) for p in data['ports'].split(',')] if data.get('ports') else None),
                '/api/ssl': lambda: ssl_certificate_info(target, int(data.get('port', 443))),
                '/api/headers': lambda: http_headers_analysis(target),
                '/api/geo': lambda: ip_geolocation(target),
                '/api/subdomains': lambda: subdomain_enum(target),
                '/api/email': lambda: email_osint(target),
                '/api/username': lambda: username_osint(target),
                '/api/network': lambda: network_analysis(target),
                '/api/robots': lambda: robots_sitemap_analysis(target),
                '/api/dorks': lambda: google_dorks(target),
                '/api/threat': lambda: threat_intelligence(target),
                '/api/metadata': lambda: metadata_extractor(target),
                '/api/hash': lambda: hash_analyzer(target),
                '/api/timeline': lambda: domain_timeline(target),
                '/api/asn': lambda: asn_lookup(target),
                '/api/full_recon': lambda: full_recon(target),
            }
            if path not in routes:
                self.send_json({'error': 'Endpoint inconnu'}, 404); return
            result = routes[path]()
            result['_elapsed'] = round(time.time() - start, 2)
            result['_timestamp'] = datetime.now().isoformat()
            self.send_json(result)
        except Exception as e:
            self.send_json({'error': str(e), 'type': type(e).__name__}, 500)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()


def main():
    port = 8765
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║         PHANTOM OSINT Framework v3.0 — 18 MODULES            ║
╠═══════════════════════════════════════════════════════════════╣
║  URL    : http://localhost:{port}                              ║
║  Modules: WHOIS · DNS · Ports · SSL · Headers · Geo          ║
║           Subdomains · Email · Username · Network             ║
║           Robots · Dorks · Threat · Metadata                  ║
║           Hash · Timeline · ASN · Full Recon                  ║
╚═══════════════════════════════════════════════════════════════╝
⚠ Usage autorisé uniquement sur des systèmes que vous possédez.
""")
    server = HTTPServer(('0.0.0.0', port), OSINTHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Arrêt de PHANTOM OSINT v3.0...")
        server.shutdown()

if __name__ == '__main__':
    main()
