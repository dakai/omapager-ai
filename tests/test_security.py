import argparse
import importlib.machinery
import importlib.util
import io
import contextlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import omapager_http as net
import omapager_files as files

def module(name):
    loader=importlib.machinery.SourceFileLoader(name,str(ROOT/'bin'/name))
    spec=importlib.util.spec_from_loader(name,loader)
    mod=importlib.util.module_from_spec(spec);loader.exec_module(mod);return mod

class Storage(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.home=Path(self.tmp.name)
        self.env=dict(os.environ,HOME=str(self.home),PYTHONDONTWRITEBYTECODE='1')
    def tearDown(self): self.tmp.cleanup()
    def run_store(self,*args,payload=None):
        return subprocess.run([sys.executable,str(ROOT/'bin/omapager-store'),*args],input=json.dumps(payload) if payload is not None else '',text=True,capture_output=True,env=self.env)
    def test_explicit_code_flags_redact_whole_row(self):
        for flag in ('code', 'codes'):
            entry = {'key': flag, flag: '938271', 'app': '938271',
                     'summary': '938271', 'body': '938271', 'rawBody': '&#57;38271',
                     'bodyLine': '938 271', 'groupKey': '938271',
                     'image': '/etc/passwd', 'replyTo': '938271'}
            self.assertEqual(self.run_store('put', payload=entry).returncode, 0)
            self.assertEqual(self.run_store('close', flag, 'done').returncode, 0)
        result = self.run_store('history')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({row['key']: row['body'] for row in json.loads(result.stdout)},
                         {'code': '[redacted]', 'codes': '[redacted]'})
        history = self.home/'.local/state/omarchy/omapager/history'
        for path in history.glob('*.json'):
            row = json.loads(path.read_text())
            self.assertEqual(row['summary'], 'Verification notification')
            self.assertEqual(row['body'], '[redacted]')
            for secret in ('938271', '&#57;38271', '938 271', '/etc/passwd'):
                self.assertNotIn(secret, path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.home/'.local/state/omarchy/omapager').stat().st_mode & 0o777, 0o700)
    def test_exec_argv_is_not_persisted(self):
        entry = {
            'key': 'shot',
            'app': 'omarchy-action',
            'summary': 'Screenshot saved',
            'body': 'Edit with Super + Alt + ,',
            'execArgv': json.dumps(['tensaku-edit', '/tmp/shot.png']),
        }
        self.assertEqual(self.run_store('put', payload=entry).returncode, 0)
        restored = json.loads(self.run_store('restore').stdout)[0]
        self.assertNotIn('execArgv', restored)
        self.assertEqual(self.run_store('close', 'shot', 'done').returncode, 0)
        history = json.loads(self.run_store('history').stdout)
        self.assertEqual(len(history), 1)
        self.assertNotIn('execArgv', history[0])
        self.assertNotIn('tensaku-edit', json.dumps(history[0]))
    def test_ordinary_restore_and_off(self):
        self.assertEqual(self.run_store('put',payload={'key':'n1','body':'ordinary message'}).returncode,0)
        self.assertEqual(json.loads(self.run_store('restore').stdout)[0]['body'],'ordinary message')
        self.assertEqual(self.run_store('policy',payload={'historyHours':0}).returncode,0)
        self.run_store('close','n1','done')
        self.assertEqual(json.loads(self.run_store('history').stdout),[])
    def test_symlink_and_oversize(self):
        self.run_store('restore')
        victim=self.home/'victim';victim.write_text('untouched')
        live=self.home/'.local/state/omarchy/omapager/live'
        (live/'n1.json').symlink_to(victim)
        self.assertNotEqual(self.run_store('put',payload={'key':'n1','body':'x'}).returncode,0)
        self.assertEqual(victim.read_text(),'untouched')
        self.assertNotEqual(self.run_store('put',payload={'key':'../../escape','body':'x'}).returncode,0)
        self.assertNotEqual(self.run_store('put',payload={'key':'n2','body':'x'*70000}).returncode,0)
    def test_directory_symlink(self):
        root=self.home/'.local/state/omarchy';root.mkdir(parents=True)
        target=self.home/'victim';target.mkdir()
        (root/'omapager').symlink_to(target,target_is_directory=True)
        self.assertNotEqual(self.run_store('put',payload={'key':'n1'}).returncode,0)
        self.assertEqual(list(target.iterdir()),[])
    def test_numbered_ordinary_notifications_survive_put_and_legacy_reads(self):
        cases = [
            ('Visual Studio Code', 'Build finished', 'Build 4123 completed successfully'),
            ('Assistant', 'Task finished', 'Claude Code finished build 4123'),
            ('Chat', 'New message', 'Please review the code from 2025'),
            ('VS Code', 'Build finished', 'VS Code finished build 4123'),
            ('Xcode', 'Build finished', 'Xcode build 4123 completed'),
            ('Chat', 'Review requested', 'Please review code abc123'),
            ('OTP Monitor', 'Build finished', 'Build 4123 completed successfully'),
            ('Auth', 'Verification completed successfully', 'Account ready'),
            ('Settings', 'PIN configuration updated', 'Settings saved'),
        ]
        self.assertEqual(self.run_store('restore').returncode, 0)
        state = self.home/'.local/state/omarchy/omapager'
        stamp = int(time.time() * 1000)
        for i, (app, summary, body) in enumerate(cases):
            # Real production rows carry numbered keys and derived lowercase
            # product group keys; neither belongs in the content detector.
            entry = {'key': f'notification-{4123+i}', 'app': app, 'summary': summary,
                     'body': body, 'rawBody': body, 'bodyLine': body,
                     'groupKey': app.lower(), 'source': app, 'urgency': 1}
            with self.subTest(app=app, body=body):
                self.assertEqual(self.run_store('put', payload=entry).returncode, 0)
                live = state/'live'/f'{entry["key"]}.json'
                self.assertEqual(json.loads(live.read_text()), entry)
                history = state/'history'/f'{stamp}-{entry["key"]}.json'
                for path in (live, history):
                    path.write_text(json.dumps(entry))
                    path.chmod(0o644)
                for verb in ('restore', 'history'):
                    result = self.run_store(verb)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    row = next(row for row in json.loads(result.stdout) if row['key'] == entry['key'])
                    self.assertEqual(row, entry)
                for path in (live, history):
                    self.assertEqual(json.loads(path.read_text()), entry)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_raw_and_legacy_recognised_codes_redact_whole_row(self):
        cases = [
            {'body': 'Your code is 938271'},
            {'body': 'Your code is G-938271'},
            {'body': 'Your OTP is 938 271'},
            {'body': 'Your OTP is 938\t271'},
            {'body': 'Your OTP is 938\n271'},
            {'body': 'Your OTP is 938\u00a0271'},
            {'body': 'Your code is 72-9182'},
            {'body': 'Your code is A9F3K2'},
            {'body': 'Your code is &#57;38271'},
            {'body': 'Your code is &amp;#57;38271'},
            {'body': 'Your OTP is 938<br/>271'},
            {'body': 'Your code to finish signing in to your account in this browser is 938271'},
            {'body': '938271 is your verification code'},
            {'body': 'Please confirm 938271'},
            {'body': 'Your security key is 938271'},
            {'body': 'Your Verification Code is 938271'},
            {'summary': 'Your code is', 'body': '938271'},
            {'summary': 'Your OTP is 938271'},
            {'rawBody': 'Your OTP is 938\n271', 'body': 'Open the app'},
        ]
        self.assertEqual(self.run_store('restore').returncode, 0)
        state = self.home/'.local/state/omarchy/omapager'
        stamp = int(time.time() * 1000)
        for mode in ('put', 'legacy-live', 'legacy-history'):
            expected = {}
            for i, text in enumerate(cases):
                key = f'{mode}-{i}'
                entry = {'key': key, 'urgency': 1, 'app': 'alternate-secret',
                         'groupKey': 'alternate-secret', 'bodyLine': 'alternate-secret',
                         'source': 'alternate-secret', 'appIcon': 'alternate-secret',
                         'replyTo': 'alternate-secret', 'image': '/etc/passwd', **text}
                expected[key] = {'key': key, 'urgency': 1,
                                 'summary': 'Verification notification', 'body': '[redacted]',
                                 'rawBody': '[redacted]', 'bodyLine': '[redacted]'}
                directory = 'history' if mode == 'legacy-history' else 'live'
                name = f'{stamp}-{key}.json' if directory == 'history' else f'{key}.json'
                path = state/directory/name
                with self.subTest(mode=mode, text=text):
                    if mode == 'put':
                        result = self.run_store('put', payload=entry)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        # Check before restore: a migration must not mask a put leak.
                        self.assertEqual(json.loads(path.read_text()), expected[key])
                    else:
                        path.write_text(json.dumps(entry))
                        path.chmod(0o644)
            verb = 'history' if mode == 'legacy-history' else 'restore'
            result = self.run_store(verb)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = {row['key']: row for row in json.loads(result.stdout)}
            for key, clean in expected.items():
                with self.subTest(mode=mode, key=key):
                    self.assertEqual(rows[key], clean)
                    name = f'{stamp}-{key}.json' if mode == 'legacy-history' else f'{key}.json'
                    path = state/('history' if mode == 'legacy-history' else 'live')/name
                    self.assertEqual(json.loads(path.read_text()), clean)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)

class Network(unittest.TestCase):
    def test_destinations(self):
        for u in ['file:///etc/passwd','https://u:p@example.com','https://example.com:22','https://127.1','http://169.254.169.254','https://[::1]','https://host.local','https://example.com/%250a']:
            with self.assertRaises(ValueError):net.parse_url(u)
    def test_dns(self):
        for ip in ['127.0.0.1','10.0.0.1','172.16.0.1','192.168.1.1','169.254.169.254','0.0.0.0','224.0.0.1','::1','fe80::1','fc00::1','::','::ffff:192.168.1.1']:
            family=socket.AF_INET6 if ':' in ip else socket.AF_INET
            answers=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',443)),(family,socket.SOCK_STREAM,6,'',(ip,443))]
            with patch.object(socket,'getaddrinfo',return_value=answers):
                with self.assertRaises(ValueError,msg=ip):net.resolve_public_host('example.com',443)
    def test_no_reresolve_and_tls_hostname(self):
        answer=(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',443))
        sock=MagicMock();ctx=MagicMock()
        with patch.object(socket,'socket',return_value=sock),patch.object(socket,'getaddrinfo',side_effect=AssertionError('second DNS lookup')),patch.object(net.ssl,'create_default_context',return_value=ctx):
            c=net.PinnedHTTPConnection('example.com',443,answer,time.monotonic()+net.REQUEST_DEADLINE);c.connect()
        sock.connect.assert_called_once_with(('93.184.216.34',443))
        ctx.wrap_socket.assert_called_once_with(sock,server_hostname='example.com')
    def test_redirects(self):
        for target in ['http://127.0.0.1','http://10.0.0.1','file:///etc/passwd','https://user@example.com','https://example.com:22','\nhttps://example.com']:
            with patch.object(net,'fetch_once',return_value=(None,target)):
                with self.assertRaises(ValueError,msg=target):net.fetch('https://example.com')
        with patch.object(net,'fetch_once',return_value=(None,'/again')) as f:
            with self.assertRaises(ValueError):net.fetch('https://example.com')
            self.assertEqual(f.call_count,4)
    def test_stream_limit(self):
        response=MagicMock(status=200)
        response.getheader.side_effect=lambda k,d=None: d
        response.read1.return_value=b'x'*11
        conn=MagicMock();conn.getresponse.return_value=response
        with patch.object(net,'resolve_public_answers',return_value=()),patch.object(net,'PinnedHTTPConnection',return_value=conn):
            with self.assertRaises(ValueError):net.fetch_once('https://example.com',10)
        conn.close.assert_called_once()
    def test_post_keeps_the_pinned_destination_and_refuses_redirects(self):
        response=MagicMock(status=200)
        response.getheader.side_effect=lambda k,d=None: d
        response.read1.return_value=b'{"ok":true}'
        response.isclosed.return_value=True
        conn=MagicMock();conn.getresponse.return_value=response;conn.sock=None
        conn.remaining.return_value=1.0
        answer=(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',443))
        with patch.object(net,'resolve_public_answers',return_value=[answer]),patch.object(net,'PinnedHTTPConnection',return_value=conn):
            body=net.post('https://api.example.com/v1/chat',b'{}',
                          {'Authorization':'Bearer test'},1024)
        self.assertEqual(body,b'{"ok":true}')
        method,target=conn.request.call_args[0][:2]
        self.assertEqual((method,target),('POST','/v1/chat'))
        sent=conn.request.call_args[1]['headers']
        self.assertEqual(sent['Authorization'],'Bearer test')
        self.assertEqual(sent['Host'],'api.example.com')
        # A caller cannot retarget the connection or suppress the cap.
        for overridden in ('Host','Connection','Accept-Encoding'):
            with patch.object(net,'resolve_public_answers',return_value=[answer]),patch.object(net,'PinnedHTTPConnection',return_value=conn):
                net.post('https://api.example.com/v1/chat',b'{}',{overridden:'evil'},1024)
            self.assertEqual(conn.request.call_args[1]['headers'][overridden],
                             {'Host':'api.example.com','Connection':'close',
                              'Accept-Encoding':'identity'}[overridden])
    def test_post_refuses_a_redirect_instead_of_following_it(self):
        with patch.object(net,'fetch_once',return_value=(None,'https://elsewhere.example/v1')):
            with self.assertRaises(ValueError):
                net.post('https://api.example.com/v1/chat',b'{}',{'Authorization':'Bearer t'},1024)
    def test_timeout_is_seconds_not_an_absolute_moment(self):
        # A caller passing 12 means "twelve seconds from now". Treating it as an
        # absolute deadline made every request fail instantly and report only
        # "deadline", which read as an unreachable provider.
        seen={}
        def fake(url,limit,deadline=None,headers=None,method='GET',body=None):
            seen['deadline']=deadline
            return (b'{}',None)
        before=time.monotonic()
        with patch.object(net,'fetch_once',side_effect=fake):
            net.request('https://api.example.com/v1/models','GET',1024,None,None,12.0)
        self.assertGreater(seen['deadline'], before)
        self.assertLessEqual(seen['deadline'], time.monotonic()+12.5)
        for bad in (0,-1,'12'):
            with self.assertRaises(ValueError):
                net.request('https://api.example.com/v1/models','GET',1024,None,None,bad)

class Replies(unittest.TestCase):
    def setUp(self):self.k=module('omapager-kdeconnect')
    def test_ambiguous_and_empty(self):
        a=dict(appName='Chat',text='hello',ticker='',replyId='1',path='/modules/kdeconnect/devices/device/notifications/1')
        with patch.object(self.k,'listing',return_value=[a,a]):self.assertIsNone(self.k.find('Chat','hello'))
        with patch.object(self.k,'listing',return_value=[a]):
            self.assertEqual(self.k.find('Chat','hello'),a)
            self.assertIsNone(self.k.find('Other','hello'))
            self.assertIsNone(self.k.find('Chat','something else'))
            self.assertIsNone(self.k.find('Chat',''))
    def test_path(self):
        self.assertTrue(self.k.valid_path('/modules/kdeconnect/devices/device_1/notifications/12'))
        for p in ['fake:1','/org/other','--help','; rm -rf ~','$(touch /tmp/pwned)','`touch /tmp/pwned`','/modules/kdeconnect/devices/x/notifications/1\n']:
            self.assertFalse(self.k.valid_path(p))
    def test_command_text_is_data(self):
        payloads=['; rm -rf ~','$(touch /tmp/pwned)','`touch /tmp/pwned`','--help','quotes"\n\\']
        target='/modules/kdeconnect/devices/device/notifications/1'
        for text in payloads:
            with patch.object(sys,'argv',['helper','reply',target,text,'Chat','body']),patch.object(self.k,'find',return_value={'path':target}),patch.object(self.k.subprocess,'run',return_value=MagicMock(returncode=0)) as run:
                with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(self.k.main(),0)
                self.assertEqual(run.call_args_list[0].args[0][-1],text)
                self.assertEqual(run.call_args_list[0].args[0][2],"--")
                self.assertNotIn('shell',run.call_args_list[0].kwargs)
    def test_demo_cannot_impersonate_a_real_phone_app(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Path(temp) / 'notification.json'
            files.write_json(fixture, {'token': 'a' * 32, 'created': time.time(),
                                      'appName': 'WhatsApp', 'title': 'Demo sender', 'text': 'hello'})
            with patch.object(self.k, 'FIXTURE', fixture), patch.object(self.k, 'listing', return_value=[]):
                self.assertIsNone(self.k.find('WhatsApp', 'Demo sender: hello'))
                note = self.k.find('Omapager reply demo', 'Demo sender: hello')
                self.assertIsNotNone(note)
                self.assertEqual(note['appName'], 'Omapager reply demo')

    def test_demo_rejects_replaced_and_expired_sessions(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Path(temp) / 'notification.json'
            reply = Path(temp) / 'reply.json'
            current = {'token': 'a' * 32, 'created': time.time(), 'title': 'Demo sender', 'text': 'hello'}
            files.write_json(fixture, current)
            with patch.object(self.k, 'FIXTURE', fixture), patch.object(self.k, 'REPLY_LOG', reply), \
                    patch.object(self.k, 'listing', return_value=[]):
                original = self.k.find('Omapager reply demo', 'Demo sender: hello')
                self.assertIsNotNone(original)
                current['token'] = 'b' * 32
                files.write_json(fixture, current)
                with patch.object(sys, 'argv', ['helper', 'reply', original['path'], 'must not be sent',
                                               'Omapager reply demo', 'Demo sender: hello']):
                    self.assertEqual(self.k.main(), 1)
                self.assertFalse(reply.exists())
                current['created'] = time.time() - self.k.FIXTURE_MAX_AGE - 1
                files.write_json(fixture, current)
                self.assertIsNone(self.k.find('Omapager reply demo', 'Demo sender: hello'))

class Icons(unittest.TestCase):
    def test_icon_hint_traversal(self):
        icon=module('omapager-icon')
        with patch.object(icon.glob,'glob',return_value=[]) as glob:
            icon.from_icon_theme(['../../../../etc/passwd','/etc/passwd','*','--help'])
            for call in glob.call_args_list:
                self.assertNotIn('../',call.args[0])
    def test_svg_rejected(self):
        icon=module('omapager-icon')
        with tempfile.TemporaryDirectory() as temp,patch.object(icon,'CACHE',temp),patch.object(icon,'get',return_value=(b'<svg xmlns="http://www.w3.org/2000/svg"></svg>','https://example.com')):
            self.assertIsNone(icon.fetch_site('example.com','dark'))
            self.assertEqual(list(Path(temp).iterdir()),[])
    # PR 4 review finding 2 (P2): a remote cache hit used to be trusted purely
    # because the path was inside CACHE and existed, so a cache entry written
    # by a pre-hardening build - most dangerously a raw remote SVG - would be
    # handed straight to the unsandboxed UI on every later run, bypassing the
    # raster validation a fresh fetch goes through. safe_cached_remote_icon()
    # now requires a cache hit to be exactly the validated raster this code
    # itself would have produced.
    def test_review_p2_legacy_remote_svg_cache_rejected(self):
        icon=module('omapager-icon')
        with tempfile.TemporaryDirectory() as temp:
            legacy=os.path.join(temp,'web-example-com-dark.svg')
            with open(legacy,'w') as f:
                f.write('<svg xmlns="http://www.w3.org/2000/svg"><script>evil()</script></svg>')
            index={'example.com':{'dark':legacy}}
            with patch.object(icon,'CACHE',temp), \
                 patch.object(icon,'INDEX',os.path.join(temp,'index.json')), \
                 patch.object(icon,'load_index',return_value=index), \
                 patch.object(icon,'save_index') as save_index, \
                 patch.object(icon,'fetch_site',return_value=None) as fetch_site:
                args=argparse.Namespace(source='example.com',app_icon='',app='',key='',
                                        scheme='dark',fetch=True)
                with patch.object(icon,'from_config',return_value=None), \
                     patch.object(icon,'from_icon_theme',return_value=None), \
                     patch.object(icon,'from_desktop_entries',return_value=None):
                    hit,how=icon.resolve(args)
            self.assertNotEqual(hit,legacy)
            self.assertFalse(os.path.exists(legacy),'poisoned cache entry must be deleted, not reused')
            fetch_site.assert_called_once_with('example.com','dark')
            self.assertTrue(save_index.called)
    def test_review_p2_local_theme_svg_preserved(self):
        # A trusted local theme SVG is a completely separate path
        # (from_icon_theme) and must be unaffected by remote-cache hardening.
        icon=module('omapager-icon')
        with tempfile.TemporaryDirectory() as temp:
            theme_dir=os.path.join(temp,'hicolor','scalable','apps')
            os.makedirs(theme_dir)
            svg_path=os.path.join(theme_dir,'kitty.svg')
            with open(svg_path,'w') as f:
                f.write('<svg xmlns="http://www.w3.org/2000/svg"></svg>')
            with patch.object(icon,'ICON_DIRS',[temp]):
                self.assertEqual(icon.from_icon_theme(['kitty']),svg_path)

class Raster(unittest.TestCase):
    def test_valid_raster_and_dimension_limit(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow not installed; run locked scanner/test environment")
        icon=module('omapager-icon')
        for size,accepted in [((256,256),True),((2049,1),False)]:
            buf=io.BytesIO();Image.new('RGB',size).save(buf,format='PNG')
            with tempfile.TemporaryDirectory() as temp,patch.object(icon,'CACHE',temp),patch.object(icon,'get',return_value=(buf.getvalue(),'https://example.com')):
                path=icon.fetch_site('example.com','dark')
                self.assertEqual(bool(path),accepted)
                if path:
                    with Image.open(path) as im:
                        self.assertEqual(im.format,'PNG')
                        self.assertLessEqual(max(im.size),128)
                    self.assertEqual(Path(path).stat().st_mode&0o777,0o600)

class CjkCodes(unittest.TestCase):
    """The Python mirror must agree with Detect.js on CJK, or a code that the
    card offers would not be redacted on its way to disk."""
    def setUp(self):
        self.store = module('omapager-store')
    def test_cjk_verification_texts_are_codes(self):
        for text in ['【某某】您的验证码是123456，5分钟内有效。',
                     '验证码：654321，请勿泄漏',
                     '您的驗證碼為 938271',
                     '您的激活码是 A9F3K2，请在30天内使用',
                     '認証コードは 482913 です',
                     '인증번호 938271 을 입력하세요']:
            with self.subTest(text=text):
                self.assertTrue(self.store.looks_like_a_code(text))
    def test_ordinary_cjk_text_is_not_a_code(self):
        for text in ['密码错误，请重试', '您的快递已到，取件码1234', 'パスワードが違います']:
            with self.subTest(text=text):
                self.assertFalse(self.store.looks_like_a_code(text))
    def test_a_cjk_code_redacts_the_stored_row(self):
        entry = {'key': 'zh1', 'summary': '短信', 'body': '您的验证码是 938271，请勿泄漏'}
        clean = self.store.sanitise(entry)
        self.assertEqual(clean['summary'], 'Verification notification')
        self.assertEqual(clean['body'], '[redacted]')
        self.assertNotIn('938271', str(clean))

class ModelPrompt(unittest.TestCase):
    """The model can only answer "is this a duplicate" if it is shown both.

    It used to be asked that question while being shown only the new message,
    so it answered "no" every time and the duplicate stage could never fire.
    """
    def setUp(self):
        self.llm = module('omapager-llm')
        self.seen = {}
    def _capture(self, url, path, body, api_key, method='POST'):
        self.seen['body'] = json.loads(body)
        return json.dumps({"choices": [{"message": {"content":
            '{"duplicate": true, "buttons": [{"kind": "link", "value": "https://x"}]}'}}]}).encode()
    def test_pair_prompt_carries_both_notifications(self):
        with patch.object(self.llm, '_request', side_effect=self._capture):
            answer = self.llm.ask('custom', 'https://example.com/v1', 'm',
                                  'B body text', 'k', 'A body text')
        prompt = self.seen['body']['messages'][0]['content']
        self.assertIn('<<<A', prompt)
        self.assertIn('<<<B', prompt)
        self.assertIn('A body text', prompt)
        self.assertIn('B body text', prompt)
        self.assertIn('duplicate', prompt)
        self.assertTrue(answer['duplicate'])
    def test_single_prompt_does_not_invite_a_duplicate_guess(self):
        with patch.object(self.llm, '_request', side_effect=self._capture):
            self.llm.ask('custom', 'https://example.com/v1', 'm', 'only text', 'k', None)
        prompt = self.seen['body']['messages'][0]['content']
        self.assertNotIn('<<<A', prompt)
        self.assertIn('only text', prompt)
        self.assertIn('always false', prompt)
    def test_systemone_judge_posts_one_question_and_thresholds(self):
        seen = {}
        def capture(url, path, body, key, method='POST'):
            seen['url'] = url
            seen['path'] = path
            seen['body'] = json.loads(body)
            value = seen.pop('noul', 0.9)
            return json.dumps({'answers': {'same_event': {'type': 'noul', 'noul': value}}}).encode()
        with patch.object(self.llm, '_request', side_effect=capture):
            seen_noul = None
            result = self.llm.judge('custom', 'https://example.com/v1', 'group/jev',
                                    'B text', 'k', 'A text')
        self.assertEqual(seen['path'], '/systemone')
        self.assertEqual(seen['body']['model'], 'group/jev')
        self.assertEqual(set(seen['body']['questions']), {'same_event'})
        self.assertEqual(seen['body']['questions']['same_event']['type'], 'noul')
        self.assertEqual(seen['body']['state'], {'a': 'A text', 'b': 'B text'})
        self.assertTrue(result['duplicate'])
        self.assertGreaterEqual(result['noul'], self.llm.NOUL_YES)
        # The threshold is a decision, so it is asserted rather than assumed.
        for value, expected in ((0.03, False), (0.699, False), (0.7, True), (0.99, True)):
            seen['noul'] = value
            with patch.object(self.llm, '_request', side_effect=capture):
                self.assertIs(self.llm.judge('custom', 'https://example.com/v1', 'g', 'B', 'k', 'A')['duplicate'],
                              expected, value)
    def test_systemone_answer_must_be_a_probability(self):
        for payload in ({'answers': {}},
                        {'answers': {'same_event': {'noul': 'yes'}}},
                        {'answers': {'same_event': {'noul': True}}},
                        {}):
            with self.subTest(payload=payload):
                with patch.object(self.llm, '_request',
                                  return_value=json.dumps(payload).encode()):
                    with self.assertRaises(ValueError):
                        self.llm.judge('custom', 'https://example.com/v1', 'g', 'B', 'k', 'A')
    def test_unparseable_answers_are_empty_not_errors(self):
        for content in ('', 'no json here', '```json\n{}\n```', '{"duplicate": "yes"}'):
            with self.subTest(content=content):
                answer = self.llm.normalise(content)
                self.assertIn('duplicate', answer)
                self.assertIsInstance(answer['buttons'], list)
                self.assertIs(answer['duplicate'], False)

class Sensitive(unittest.TestCase):
    def setUp(self):
        self.store=module('omapager-store')
    def test_credentials_are_detected_and_personal_data_is_optional(self):
        for text in ['token '+'sk-'+'a'*30, 'github '+'ghp_'+'a'*36,
                     'redis://:'+'hunter2'+'@cache:6379',
                     'jwt '+'eyJ'+'a'*10+'.eyJ'+'b'*10+'.'+'c'*10,
                     'card 4111111111111111']:
            with self.subTest(text=text):
                self.assertTrue(self.store.contains_sensitive(text))
        # Personal data is hidden on screen but not used to blank a history row.
        for text in ['mail user@example.com', 'phone +1 415 555 0100']:
            with self.subTest(text=text):
                self.assertFalse(self.store.contains_sensitive(text))
                self.assertTrue(self.store.contains_sensitive(text, personal=True))
    def test_ordinary_text_is_not_a_credential(self):
        for text in ['code 412 passed', 'Claude Code 412', 'build 1234 5678 9012 3456',
                     'version 1.2.3', 'nothing to see here']:
            with self.subTest(text=text):
                self.assertFalse(self.store.contains_sensitive(text))
    def test_credential_redacts_the_whole_entry_but_keeps_the_key(self):
        entry={'key':'k1','summary':'Here is your key','body':'token sk-'+'a'*30,
               'rawBody':'token sk-'+'a'*30,'bodyLine':'token sk-'+'a'*30,'app':'Terminal'}
        clean=self.store.sanitise(entry)
        self.assertEqual(clean['key'],'k1')
        self.assertEqual(clean['summary'],'Verification notification')
        self.assertEqual(clean['body'],'[redacted]')
        self.assertNotIn('sk-',''.join(str(v) for v in clean.values()))
    def test_personal_data_alone_does_not_destroy_a_history_row(self):
        entry={'key':'k2','summary':'Thanks','body':'reply to user@example.com please'}
        clean=self.store.sanitise(entry)
        self.assertEqual(clean['body'],'reply to user@example.com please')

if __name__=='__main__':unittest.main()
