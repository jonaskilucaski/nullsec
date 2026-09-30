"""Offline regression tests. Every network/scanner executable is a local stub."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
STUB = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
def arg(flag):
    return args[args.index(flag)+1] if flag in args else None
targets=[]
for flag in ('-l','-list','-m'):
    if arg(flag): targets=pathlib.Path(arg(flag)).read_text().splitlines()
if arg('-u'): targets=[arg('-u')]
if name=='dalfox': targets=sys.stdin.read().splitlines()
with open(os.environ['CALL_LOG'],'a') as f:
    f.write(json.dumps({'tool':name,'args':args,'targets':targets})+'\n')
if name=='dnsx' and '-h' in args:
    print(os.environ.get('DNS_HELP','-l -o -silent -auto-wildcard -wd -wildcard-domain'))
    sys.exit(int(os.environ.get('DNS_HELP_STATUS','0')))
if name=='httpx-toolkit':
    mode=os.environ.get('HTTPX_MODE','pass')
    output=arg('-o')
    if mode=='empty': targets=[]
    lines=[x if x.startswith(('http://','https://')) else 'https://'+x for x in targets]
    if '-sc' in args or '-status-code' in args: lines=[x+' [200]' for x in lines]
    text=''.join(x+'\n' for x in lines)
    if output: pathlib.Path(output).write_text(text)
    else: print(text,end='')
    sys.exit(1 if mode=='fail' else 0)
if name=='naabu' and arg('-o'):
    pathlib.Path(arg('-o')).write_text(os.environ.get('NAABU_OUTPUT',''))
elif name=='dnsx':
    pathlib.Path(arg('-o')).write_text(''.join(x+' [A] [192.0.2.1]\n' for x in targets))
elif name=='curl':
    body=os.environ.get('CURL_BODY','const example = true;')
    if arg('-o'): pathlib.Path(arg('-o')).write_text(body)
    if arg('-w'): print(os.environ.get('CURL_STATUS','200'),end='')
    elif not arg('-o'): print(body)
    sys.exit(int(os.environ.get('CURL_EXIT_STATUS','0')))
elif name=='dig':
    print(os.environ.get('DIG_RESULT',''))
elif name in ('waybackurls','gau'):
    print(os.environ.get('PASSIVE_URLS',''),end='')
elif name=='trufflehog':
    for verified,error in ((True,None),(False,None),(False,'unavailable')):
        print(json.dumps({'Verified':verified,'VerificationError':error,
            'DetectorName':'Fixture','SourceMetadata':{'Data':{'Filesystem':{'file':'fixture.js'}}}}))
elif name=='arjun' and '-h' in args:
    print('--disable-redirects')
'''


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.log = self.base / 'calls.jsonl'
        self.log.touch()
        for tool in ('curl', 'dnsx', 'httpx-toolkit', 'dig', 'waybackurls', 'gau',
                     'katana', 'hakrawler', 'cariddi', 'gowitness', 'nuclei',
                     'dalfox', 'sqlmap', 'ffuf', 'arjun', 'naabu', 'trufflehog',
                     'cloud_enum', 'gf', 'qsreplace', 'subfinder', 'assetfinder',
                     'puredns', 'amass', 'amass-v4', 'gotator', 'unfurl'):
            file = self.bin / tool
            file.write_text(STUB)
            file.chmod(0o755)
        self.out = self.base / 'out'
        for directory in ('phase1-subdomains', 'phase2-validation', 'phase2.5-cloud',
                          'phase3-probing', 'phase4-portscan', 'phase5-urls',
                          'phase6-parameters', 'phase7-vulns', 'phase8-javascript',
                          'phase9-patterns', 'phase10-screenshots', 'phase11-fuzzing',
                          'phase12-active-vulns', 'reports'):
            (self.out / directory).mkdir(parents=True)
        self.env = os.environ.copy()
        for key in list(self.env):
            if key.startswith(('NULLSEC_', 'TELEGRAM_')):
                del self.env[key]
        self.env.update(PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                        CASE_DIR=str(self.base), CALL_LOG=str(self.log))

    def tearDown(self):
        self.tmp.cleanup()

    def file(self, name, text):
        path = self.base / name
        path.write_text(text)
        return path

    def run_shell(self, body, expected=0, env=None):
        setup = '''source ./nullsec.sh
trap - INT TERM
TARGET=example.com
OUTPUT_DIR="$CASE_DIR/out"
RESUME_FROM=0
CHECKPOINT_FILE="$OUTPUT_DIR/.checkpoint"
AUTHORIZATION_FINGERPRINT=""
info() { :; }; warn() { :; }; error() { :; }; success() { :; }; print_phase() { :; }
'''
        result = subprocess.run(['bash', '-c', setup+body], cwd=ROOT,
                                env=self.env | (env or {}), text=True, capture_output=True)
        if expected is not None:
            self.assertEqual(result.returncode, expected, result.stderr+result.stdout)
        return result

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_scope_omitted_and_malformed_candidates(self):
        result = self.run_shell("printf '%s\\n' example.com a.example.com evil.invalid bad..example.com https://a.example.com:443/x HTTPS://A.EXAMPLE.COM/x https://a.example.com:99999/x https://a.example.com@evil.invalid/x | in_scope")
        self.assertEqual(result.stdout.splitlines(), ['example.com','a.example.com','https://a.example.com:443/x','HTTPS://A.EXAMPLE.COM/x'])

    def test_explicit_empty_rules_deny_all(self):
        for contents in ('', '\n  # only comments\n  \n'):
            with self.subTest(contents=contents):
                self.file('include', contents)
                r = self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; printf "%s\\n" example.com a.example.com | in_scope')
                self.assertEqual(r.stdout, '')

    def test_bare_authorities_and_url_ports(self):
        self.file('include', '*.example.com\n')
        self.file('exclude', 'excluded.example.com\n')
        cases = {
            'api.example.com:443': True,
            'api.example.com:8443': True,
            'excluded.example.com:8443': False,
            'external.invalid:8443': False,
            'api.example.com:0': False,
            'api.example.com:65536': False,
            'api.example.com:https': False,
            '192.0.2.1:8443': False,
            '[2001:db8::1]:443': False,
            '[api.example.com]:443': False,
            'user@api.example.com:443': False,
            'api.example.com:443:8443': False,
            'api.example.com:8443/path': False,
            'api.example.com': True,
            'api.example.com:1': True,
            'api.example.com:65535': True,
            'http://api.example.com:8443/x': True,
            'https://api.example.com:443/x': True,
            'https://api.example.com:0/x': False,
            'https://api.example.com:65536/x': False,
            'https://user@api.example.com:443/x': False,
            'https://[api.example.com]:443/x': False,
        }
        for candidate, accepted in cases.items():
            with self.subTest(candidate=candidate):
                result = self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; '
                    'SCOPE_EXCLUDE_FILE="$CASE_DIR/exclude"; '
                    'printf "%s\\n" "$CANDIDATE" | in_scope', env={'CANDIDATE': candidate})
                self.assertEqual(result.stdout, candidate+'\n' if accepted else '')

    def test_phase4_naabu_authority_reaches_httpx_unchanged(self):
        self.file('include', 'api.example.com\n')
        (self.out/'phase2-validation/valid-subdomains.txt').write_text('api.example.com\n')
        (self.out/'phase3-probing/live-hosts.txt').touch()
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; '
            'ALLOW_ACTIVE_ENUMERATION=true; RUN_PORT_SCAN=true; '
            'polite_sleep() { :; }; phase4_portscan',
            env={'NAABU_OUTPUT': 'api.example.com:8443\n'})
        calls = self.calls()
        self.assertEqual([c['tool'] for c in calls], ['naabu', 'httpx-toolkit'])
        self.assertEqual(calls[1]['targets'], ['api.example.com:8443'])
        self.assertEqual((self.out/'phase4-portscan/services-on-ports.txt').read_text(),
                         'https://api.example.com:8443\n')

    def test_exact_wildcard_case_and_exclusion(self):
        self.file('include', 'EXAMPLE.COM.\n*.API.EXAMPLE.COM\n')
        self.file('exclude', '*.blocked.api.example.com\nexample.com\n')
        r = self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; SCOPE_EXCLUDE_FILE="$CASE_DIR/exclude"; printf "%s\\n" example.com api.example.com a.api.example.com b.a.api.example.com a.blocked.api.example.com | in_scope')
        self.assertEqual(r.stdout.splitlines(), ['a.api.example.com','b.a.api.example.com'])

    def test_malformed_host_rules_fail_without_partial_output(self):
        for bad in ('https://api.example.com','a..example.com','*example.com','*.*.example.com','-a.example.com','example.com:443','192.0.2.1'):
            with self.subTest(rule=bad):
                self.file('include', 'example.com\n'+bad+'\n')
                r = self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; printf "%s\\n" example.com | in_scope', expected=1)
                self.assertEqual(r.stdout, '')
                self.run_shell('SCOPE_EXCLUDE_FILE="$CASE_DIR/include"; main -d example.com -s', expected=1)
                self.assertEqual(self.calls(), [])

    def test_disappearing_authorization_files(self):
        for variable in ('SCOPE_INCLUDE_FILE','SCOPE_EXCLUDE_FILE','CLOUD_APPROVAL_FILE'):
            with self.subTest(variable=variable):
                self.file('rules', 's3:example-assets\n' if variable=='CLOUD_APPROVAL_FILE' else 'example.com\n')
                r=self.run_shell(f'{variable}="$CASE_DIR/rules"; AUTHORIZATION_FINGERPRINT=$(authorization_fingerprint); rm "$CASE_DIR/rules"; printf "example.com\\n" | in_scope', expected=1)
                self.assertEqual(r.stdout, '')

    def test_nonregular_and_unreadable_files(self):
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR"; printf "example.com\\n" | in_scope', expected=1)
        path=self.file('unreadable','example.com\n'); path.chmod(0)
        if os.geteuid()==0 and shutil.which('runuser'):
            self.base.chmod(0o755)
            # The unprivileged reader uses only the policy parser, no scanners.
            result=subprocess.run(['runuser','-u','nobody','--','bash','-c',
                'source "$1"; normalize_authorization_file host "$2"', 'test',
                str(ROOT/'lib/authorization.sh'),str(path)],text=True,capture_output=True)
            self.assertNotEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,'')
        else:
            self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/unreadable"; printf "example.com\\n" | in_scope', expected=1)

    def test_cloud_valid_normalized_and_empty(self):
        self.file('cloud', ' S3 : example-assets \n gcs:example_assets\nazure:examplestorage # comment\n')
        r=self.run_shell('normalize_authorization_file cloud "$CASE_DIR/cloud"')
        self.assertEqual(r.stdout.splitlines(), ['azure:examplestorage','gcs:example_assets','s3:example-assets'])
        self.file('cloud','')
        self.assertEqual(self.run_shell('normalize_authorization_file cloud "$CASE_DIR/cloud"').stdout,'')

    def test_cloud_invalid_rules(self):
        for bad in ('azure','unknown:example','s3:','s3:one:two','azure:a-b','azure:UPPERCASE','s3:192.0.2.1','s3:a..b','s3:xn--example','gcs:goog-example','gcs:my_google_bucket'):
            with self.subTest(rule=bad):
                self.file('cloud','s3:example-assets\n'+bad+'\n')
                r=self.run_shell('normalize_authorization_file cloud "$CASE_DIR/cloud"',expected=1)
                self.assertEqual(r.stdout,'')

    def test_resume_policy_identity_and_changes(self):
        self.file('include','example.com\n*.example.com\n')
        self.file('cloud','s3:example-assets\n')
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; CLOUD_APPROVAL_FILE="$CASE_DIR/cloud"; AUTHORIZATION_FINGERPRINT=$(authorization_fingerprint); printf "AUTHORIZATION_SHA256=%s\\n" "$AUTHORIZATION_FINGERPRINT" > "$CASE_DIR/meta"; check_resume_authorization "$CASE_DIR/meta"')
        self.file('include',' # reordered\n*.EXAMPLE.COM.\nexample.com\nexample.com\n')
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; CLOUD_APPROVAL_FILE="$CASE_DIR/cloud"; AUTHORIZATION_FINGERPRINT=$(authorization_fingerprint); check_resume_authorization "$CASE_DIR/meta"')
        for body in ('SCOPE_INCLUDE_FILE="$CASE_DIR/narrow"', 'SCOPE_INCLUDE_FILE=""',
                     'CLOUD_APPROVAL_FILE="$CASE_DIR/cloud2"', 'ALLOW_ACTIVE_ENUMERATION=true',
                     'ALLOW_ACTIVE_VALIDATION=true', 'ALLOW_SECRET_VERIFICATION=true'):
            with self.subTest(change=body):
                self.file('narrow','api.example.com\n');self.file('cloud2','s3:other-assets\n')
                self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; CLOUD_APPROVAL_FILE="$CASE_DIR/cloud"; '+body+'; AUTHORIZATION_FINGERPRINT=$(authorization_fingerprint); check_resume_authorization "$CASE_DIR/meta"',expected=1)
        self.file('oldmeta','TARGET=example.com\nSCAN_MODE=normal\n')
        self.run_shell('AUTHORIZATION_FINGERPRINT=$(authorization_fingerprint); check_resume_authorization "$CASE_DIR/oldmeta"',expected=1)

    def test_policy_change_during_execution(self):
        self.file('include','*.example.com\n')
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; AUTHORIZATION_FINGERPRINT=$(authorization_fingerprint); printf "api.example.com\\n" > "$CASE_DIR/include"; curl https://example.com',expected=1)
        self.assertEqual(self.calls(),[])

    def test_authorization_classes_and_modes(self):
        for mode in ('fast','normal','deep'):
            with self.subTest(mode=mode):
                r=self.run_shell(f'SCAN_MODE={mode}; apply_scan_mode; printf "%s\\n" "$RUN_PORT_SCAN" "$RUN_PARAM_DISCOVERY" "$RUN_VHOST_DISCOVERY" "$RUN_FUZZING" "$RUN_ACTIVE_VULNS"')
                self.assertEqual(r.stdout.splitlines(),['false']*5)
        r=self.run_shell('SCAN_MODE=deep; ALLOW_ACTIVE_ENUMERATION=true; apply_scan_mode; printf "%s\\n" "$RUN_PARAM_DISCOVERY" "$RUN_FUZZING" "$RUN_ACTIVE_VULNS"')
        self.assertEqual(r.stdout.splitlines(),['true','true','false'])
        r=self.run_shell('SCAN_MODE=deep; ALLOW_ACTIVE_VALIDATION=true; apply_scan_mode; printf "%s\\n" "$RUN_FUZZING" "$RUN_ACTIVE_VULNS"')
        self.assertEqual(r.stdout.splitlines(),['false','true'])
        self.file('targets','https://api.example.com/\n')
        for invocation in ('ffuf -u https://api.example.com/FUZZ','arjun -u https://api.example.com/',
                           'naabu -list "$CASE_DIR/targets"','sqlmap -m "$CASE_DIR/targets"',
                           'nuclei -l "$CASE_DIR/targets"','printf "https://api.example.com/\\n" | dalfox pipe'):
            self.run_shell(invocation,expected=1)
        self.assertEqual(self.calls(),[])

    def test_launch_inputs_are_scoped_and_redirects_restricted(self):
        self.file('include','api.example.com\n')
        self.file('targets','https://api.example.com/x\nhttps://excluded.example.com/x\nhttps://external.invalid/x\n')
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; httpx-toolkit -l "$CASE_DIR/targets" -follow-host-redirects -o "$CASE_DIR/result"')
        call=self.calls()[0]
        self.assertEqual(call['targets'],['https://api.example.com/x'])
        self.assertIn('-fr=false',call['args']);self.assertIn('-fhr=true',call['args'])
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; ALLOW_ACTIVE_ENUMERATION=true; ffuf -u https://excluded.example.com/FUZZ',expected=1)
        self.assertEqual(len(self.calls()),1)

    def test_cloud_evidence_and_exact_provider_approval(self):
        self.file('include','api.example.com\n')
        (self.out/'phase2-validation/valid-subdomains.txt').write_text('api.example.com\n')
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; phase2_5_cloud_enum',env={'CURL_BODY':'example-assets.s3.amazonaws.com'})
        calls=self.calls()
        urls=[a for c in calls if c['tool']=='curl' for a in c['args'] if a.startswith(('http://','https://'))]
        self.assertEqual(urls,['https://api.example.com/'])
        self.log.write_text('')
        self.file('cloud','gcs:example-assets\n')
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; CLOUD_APPROVAL_FILE="$CASE_DIR/cloud"; phase2_5_cloud_enum',env={'CURL_BODY':'example-assets.s3.amazonaws.com'})
        self.assertFalse(any('amazonaws.com' in a for c in self.calls() if c['tool']=='curl' for a in c['args']))

    def test_nuclei_launcher_scopes_seeds_and_forces_redirect_control(self):
        self.file('include', 'api.example.com\n')
        self.file('targets', 'https://api.example.com:8443/x\nhttps://external.invalid/x\n')
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; ALLOW_ACTIVE_VALIDATION=true; '
            'nuclei -l "$CASE_DIR/targets" -fr -fhr -dr=false; '
            'nuclei -u https://api.example.com:8443/x')
        calls = self.calls()
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertEqual(call['tool'], 'nuclei')
            self.assertEqual(call['targets'], ['https://api.example.com:8443/x'])
            self.assertEqual(call['args'][-1], '-dr=true')
        self.assertGreater(calls[0]['args'].index('-dr=true'),
                           calls[0]['args'].index('-dr=false'))
        self.run_shell('ALLOW_ACTIVE_VALIDATION=true; nuclei -u https://external.invalid/', expected=1)
        self.assertEqual(len(self.calls()), 2)

    def test_approved_cloud_workers_inherit_curl_policy(self):
        self.file('include','api.example.com\n')
        self.file('cloud','s3:example-assets\ngcs:example-public\nazure:examplestorage\n')
        (self.out/'phase2-validation/valid-subdomains.txt').write_text('api.example.com\n')
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; CLOUD_APPROVAL_FILE="$CASE_DIR/cloud"; AUTHORIZATION_FINGERPRINT=$(authorization_fingerprint); phase2_5_cloud_enum',
                       env={'CURL_BODY':'example-assets.s3.amazonaws.com example-public.storage.googleapis.com examplestorage.blob.core.windows.net'})
        calls=[c for c in self.calls() if c['tool']=='curl']
        provider_calls=[c for c in calls if any('amazonaws.com' in a or 'googleapis.com' in a or 'windows.net' in a for a in c['args'])]
        self.assertTrue(provider_calls)
        for call in provider_calls:
            self.assertEqual(call['args'][0],'--disable')
            self.assertIn('--no-location',call['args'])
        self.assertTrue(any('s3.amazonaws.com' in a for c in provider_calls for a in c['args']))
        self.assertTrue(any('storage.googleapis.com' in a for c in provider_calls for a in c['args']))
        self.assertTrue(any('blob.core.windows.net' in a for c in provider_calls for a in c['args']))

    def test_positive_enumeration_launches_remain_bounded(self):
        self.file('include','api.example.com\n')
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; ALLOW_ACTIVE_ENUMERATION=true; ffuf -u https://api.example.com/FUZZ; arjun -u https://api.example.com/')
        ffuf=[c for c in self.calls() if c['tool']=='ffuf'][0]
        self.assertIn('-r=false',ffuf['args']);self.assertIn('-recursion=false',ffuf['args'])
        arjun=[c for c in self.calls() if c['tool']=='arjun'][0]
        self.assertIn('--disable-redirects',arjun['args'])

    def test_disabled_vhost_and_browser_paths(self):
        (self.out/'phase2-validation/valid-subdomains.txt').write_text('api.example.com\n')
        self.run_shell('ALLOW_ACTIVE_ENUMERATION=true; SCAN_MODE=deep; apply_scan_mode; phase3_probing; phase10_screenshots')
        self.assertFalse(any(c['tool'] in ('ffuf','gowitness') for c in self.calls()))

    def test_missing_or_changed_validation_marker_blocks_consumers(self):
        p5=self.out/'phase5-urls'
        (p5/'live-js-files.txt').write_text('https://api.example.com/app.js\n')
        (p5/'all-urls-injectable.txt').write_text('https://api.example.com/?q=1\n')
        self.run_shell('ALLOW_ACTIVE_VALIDATION=true; phase9_pattern_hunting',expected=1)
        self.run_shell('phase8_javascript_analysis',expected=1)
        (p5/'validation-state.txt').write_text('status=complete\nauthorization=wrong\n')
        self.run_shell('ALLOW_ACTIVE_VALIDATION=true; phase9_pattern_hunting',expected=1)
        self.assertEqual(self.calls(),[])

    def test_explicit_dns_policy_does_not_generate_wildcard_probes(self):
        self.file('include','api.example.com\n')
        (self.out/'phase1-subdomains/all-subdomains.txt').write_text('api.example.com\nexample.com\n')
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; phase2_validation')
        call=[c for c in self.calls() if c['tool']=='dnsx' and '-h' not in c['args']][0]
        self.assertEqual(call['targets'],['api.example.com'])
        self.assertNotIn('-auto-wildcard',call['args']);self.assertNotIn('-wd',call['args'])
        self.file('include','')
        self.log.write_text('')
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; phase2_validation')
        self.assertEqual(self.calls(),[])

    def test_js_redirect_and_failed_download_are_not_promoted(self):
        p5=self.out/'phase5-urls'
        (p5/'live-js-files.txt').write_text('https://api.example.com/app.js\n')
        for status,exit_status in (('302','0'),('200','1')):
            with self.subTest(status=status,exit_status=exit_status):
                self.log.write_text('')
                self.run_shell('printf "status=complete\\nauthorization=%s\\n" "$(authorization_fingerprint)" > "$OUTPUT_DIR/phase5-urls/validation-state.txt"; phase8_javascript_analysis',
                               expected=1,env={'CURL_STATUS':status,'CURL_EXIT_STATUS':exit_status})
                self.assertFalse(any(c['tool']=='trufflehog' for c in self.calls()))

    def phase5(self, mode='pass', urls='https://api.example.com/app.js\nhttps://api.example.com/?q=1\n'):
        (self.out/'phase3-probing/live-hosts.txt').write_text('https://api.example.com\n')
        (self.out/'phase2-validation/valid-subdomains.txt').write_text('api.example.com\n')
        return self.run_shell('phase5_url_discovery',expected=None,
                              env={'HTTPX_MODE':mode,'PASSIVE_URLS':urls})

    def test_httpx_missing_failure_empty_and_evidence(self):
        p5=self.out/'phase5-urls'
        for mode in ('missing','fail','empty'):
            with self.subTest(mode=mode):
                binary=self.bin/'httpx-toolkit'
                if mode=='missing': binary.rename(self.bin/'saved-httpx')
                result=self.phase5(mode)
                if mode=='missing': (self.bin/'saved-httpx').rename(binary)
                self.assertEqual(result.returncode,0 if mode=='empty' else 1,result.stderr)
                for name in ('all-urls.txt','all-urls-injectable.txt','live-js-files.txt'):
                    self.assertEqual((p5/name).read_text(),'')
                self.assertTrue((p5/'all-urls-raw.txt').read_text())
                self.assertTrue((p5/'scoped-injectable-candidates.txt').read_text())

    def test_stale_js_cloud_feed_and_crawlers(self):
        p5=self.out/'phase5-urls'
        (p5/'live-js-files.txt').write_text('https://api.example.com/old.js\n')
        cloud=self.out/'phase2.5-cloud/exposed';cloud.mkdir()
        (cloud/'cloud-urls-for-phase5.txt').write_text('https://unapproved.storage.googleapis.com/\n')
        r=self.phase5(urls='https://api.example.com/?q=1\n')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual((p5/'live-js-files.txt').read_text(),'')
        self.assertNotIn('googleapis',(p5/'all-urls-raw.txt').read_text())
        self.assertFalse(any(c['tool'] in ('katana','hakrawler','cariddi') for c in self.calls()))

    def test_injectable_consumers_intersect_stale_gf(self):
        p5=self.out/'phase5-urls'
        (p5/'all-urls-injectable.txt').write_text('https://api.example.com/?q=1\nhttps://excluded.example.com/?q=2\n')
        (p5/'all-urls.txt').touch()
        (p5/'gf-xss.txt').write_text('https://api.example.com/?q=1\nhttps://api.example.com/?q=stale\nhttps://excluded.example.com/?q=2\n')
        self.file('include','api.example.com\n')
        self.run_shell('SCOPE_INCLUDE_FILE="$CASE_DIR/include"; ALLOW_ACTIVE_VALIDATION=true; printf "status=complete\\nauthorization=%s\\n" "$(authorization_fingerprint)" > "$OUTPUT_DIR/phase5-urls/validation-state.txt"; phase9_pattern_hunting')
        dalfox=[c for c in self.calls() if c['tool']=='dalfox']
        self.assertEqual(len(dalfox),1)
        self.assertEqual(dalfox[0]['targets'],['https://api.example.com/?q=1'])

    def test_dnsx_contract_branches_and_failures(self):
        for helptext,status,expected in (('-l -o -silent -auto-wildcard -wd -wildcard-domain',0,'auto'),
                                         ('-l -o -silent -wd -wildcard-domain',0,'manual'),
                                         ('-auto-wildcard',2,None),('unexpected',0,None)):
            with self.subTest(help=helptext,status=status):
                r=self.run_shell('dnsx_wildcard_mode',expected=0 if expected else 1,
                                 env={'DNS_HELP':helptext,'DNS_HELP_STATUS':str(status)})
                if expected:self.assertEqual(r.stdout.strip(),expected)
        for helptext,flag in (('-l -o -silent -auto-wildcard','-auto-wildcard'),('-l -o -silent -wd -wildcard-domain','-wd')):
            self.log.write_text('')
            (self.out/'phase1-subdomains/all-subdomains.txt').write_text('example.com\nevil.invalid\n')
            self.run_shell('phase2_validation',env={'DNS_HELP':helptext})
            call=[c for c in self.calls() if c['tool']=='dnsx' and '-h' not in c['args']][0]
            self.assertEqual(call['targets'],['example.com']);self.assertIn(flag,call['args'])
            if flag=='-wd':self.assertEqual(call['args'][call['args'].index('-wd')+1],'example.com')

    def test_curl_configuration_and_secret_verification(self):
        self.run_shell('curl -L https://example.com/')
        call=self.calls()[0]
        self.assertEqual(call['args'][0],'--disable')
        self.assertGreater(call['args'].index('--no-location'),call['args'].index('-L'))
        for authorized in ('false','true'):
            self.log.write_text('')
            (self.out/'phase5-urls/live-js-files.txt').write_text('https://api.example.com/app.js\n')
            self.run_shell(f'ALLOW_SECRET_VERIFICATION={authorized}; printf "status=complete\\nauthorization=%s\\n" "$(authorization_fingerprint)" > "$OUTPUT_DIR/phase5-urls/validation-state.txt"; phase8_javascript_analysis')
            call=[c for c in self.calls() if c['tool']=='trufflehog'][0]
            self.assertEqual('--no-verification' in call['args'],authorized=='false')
            summary=(self.out/'phase8-javascript/trufflehog-summary.txt').read_text()
            self.assertIn('[verified]',summary);self.assertIn('[unverified]',summary);self.assertIn('[unknown]',summary)


if __name__ == '__main__':
    unittest.main()
