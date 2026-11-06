import contextlib
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from walletguard import triage
from walletguard.__main__ import main
from walletguard.findings import Finding


class Triage(unittest.TestCase):
    @contextlib.contextmanager
    def server(self, payload=None, status=200):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append((self.path, json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                self.send_response(status)
                self.send_header('Location', 'http://8.8.8.8:11434/api/chat')
                self.end_headers()
                self.wfile.write(json.dumps(payload or {
                    'message': {'content': json.dumps({'commentary': ['Review rank 1: check the executable.']})}
                }).encode())

            def log_message(self, *args):
                pass

        with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield f'http://127.0.0.1:{server.server_port}', requests
            finally:
                server.shutdown()
                thread.join()

    def test_fake_ollama_projection_and_commentary(self):
        f = Finding('high', 'process', 'SYNTHETIC_PRIVATE_TITLE', 'SYNTHETIC_PRIVATE_DETAIL',
                    'SYNTHETIC_PRIVATE_FIX', {'path': r'C:\Temp\app.exe',
                                              'command': 'SYNTHETIC_PRIVATE_COMMAND',
                                              'token': 'SYNTHETIC_PRIVATE_TOKEN'})
        before = f.to_dict()
        with self.server() as (endpoint, requests):
            result = triage.explain([f], endpoint)
        self.assertIn('Review rank 1', result[0])
        self.assertEqual(f.to_dict(), before)
        path, body = requests[0]
        self.assertEqual(path, '/api/chat')
        self.assertFalse(body['stream'])
        self.assertNotIn('SYNTHETIC_PRIVATE', json.dumps(body))
        self.assertEqual(json.loads(body['messages'][1]['content']), [{
            'type': 'process', 'path': r'C:\Temp\app.exe', 'severity': 'high',
            'evidence_summary': triage.SUMMARIES['process']}])

    def test_endpoints(self):
        for endpoint in ('http://127.0.0.1:11434', 'http://192.168.1.4:11434',
                         'http://10.0.0.2:11434', 'https://[fd00::1]:11434',
                         'http://[::1]:11434', 'http://localhost:11434'):
            triage.endpoint_address(endpoint)
        for endpoint in ('http://8.8.8.8:11434', 'http://0.0.0.0:11434',
                         'http://169.254.169.254:80', 'http://example.com:11434',
                         'http://box.ts.net:11434', 'http://[::ffff:8.8.8.8]:11434',
                         'http://user:pass@127.0.0.1:11434', 'http://127.0.0.1:11434/api',
                         'http://127.0.0.1:11434?secret=x', 'ftp://127.0.0.1:11434',
                         'http://127.0.0.1', 'http://127.0.0.1:99999'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                triage.explain([Finding('high', 'process', '')], endpoint)

    def test_no_redirects_or_environment_proxy(self):
        with self.server(status=302) as (endpoint, requests), patch.dict(
                'os.environ', {'HTTP_PROXY': 'http://8.8.8.8:80'}):
            self.assertEqual(triage.explain([Finding('low', 'scanner', '')], endpoint), {})
            self.assertEqual(len(requests), 1)

    def test_failure_and_bad_replies(self):
        f = Finding('high', 'process', '')
        for payload in ({'message': {'content': 'invalid'}}, {'message': {'content': '{}'}},
                        {'message': {'content': '{"commentary": [42]}'}},
                        {'message': {'content': '{"commentary": []}'}}):
            with self.server(payload) as (endpoint, _):
                self.assertEqual(triage.explain([f], endpoint), {})
        with patch('http.client.HTTPConnection.request', side_effect=TimeoutError):
            self.assertEqual(triage.explain([f]), {})

    def test_paths_and_unknown_types_are_restricted(self):
        for path in ('https://example.com', 'cmd /c secret', 'C:\\x\nsecret',
                     'C:\\x:secret', None):
            self.assertEqual(triage.project(Finding('high', 'unknown secret', '',
                             data={'path': path}))['path'], '')
        self.assertEqual(triage.project(Finding('high', 'unknown secret', ''))['type'], 'scanner')

    def test_cli_opt_in_fallback_and_severity(self):
        f = Finding('high', 'process', 'Test executable')
        with tempfile.TemporaryDirectory() as directory, patch('walletguard.__main__.DATA_DIR', directory), \
                patch('walletguard.scanner.full_scan', return_value=[f]), \
                patch('walletguard.triage.explain', return_value={}) as explain:
            with contextlib.redirect_stdout(io.StringIO()) as baseline:
                self.assertEqual(main(['scan']), 2)
            explain.assert_not_called()
            with contextlib.redirect_stdout(io.StringIO()) as fallback:
                self.assertEqual(main(['scan', '--explain']), 2)
            self.assertEqual(baseline.getvalue().split('Full report:')[0],
                             fallback.getvalue().split('Full report:')[0])
            explain.return_value = {0: 'Review rank 1: check this program.'}
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(['scan', '--explain']), 2)
            self.assertIn('AI commentary (unverified; not a safety verdict)', output.getvalue())
            self.assertEqual(f.severity, 'high')
            with contextlib.redirect_stdout(io.StringIO()) as output:
                main(['scan', '--explain', '--json'])
            report = json.loads(output.getvalue().split('\n', 2)[2])
            self.assertEqual(report[0]['ai_commentary'], explain.return_value[0])

    def test_cli_with_fake_server_and_saved_report(self):
        from pathlib import Path
        f = Finding('high', 'process', 'Test executable')
        with self.server() as (endpoint, requests), tempfile.TemporaryDirectory() as directory, \
                patch('walletguard.__main__.DATA_DIR', directory), \
                patch('walletguard.scanner.full_scan', return_value=[f]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['scan', '--explain', '--ollama-endpoint', endpoint]), 2)
            self.assertEqual(len(requests), 1)
            self.assertIn('AI commentary', output.getvalue())
            report = json.loads(next(Path(directory).glob('scan-*.json')).read_text())
            self.assertEqual(report[0]['severity'], 'high')
            self.assertIn('Review rank 1', report[0]['ai_commentary'])


if __name__ == '__main__':
    unittest.main()
