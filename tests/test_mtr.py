"""Offline regression tests: no DNS, MTR packets, installs, or API requests.

Run with python3 -m unittest discover -s tests -v.
EGRESS_TEST_AWK can select gawk, mawk, or 'busybox awk'.
"""
import os
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'ip.sh').read_text()


def function(name):
    start = SOURCE.index(name + '() {')
    end = SOURCE.index('\n}', start) + 2
    return SOURCE[start:end]


CORE = '\n'.join(function(n) for n in (
    'run_mtr_report', 'resolve_mtr_target', 'parse_mtr_report',
    'first_public_hop', 'detect_mtr_base_asn'))


def row(ip, loss='0.0', avg='9.0', sent=3):
    return f'{ip} {loss}% {sent} 1.0 {avg} 0.1 10.0 0.2'


def report(*rows):
    return ('Start: 2026-09-14T06:01:00+0000\n'
            'HOST: test-vps Loss% Snt Last Avg Best Wrst StDev\n'
            + ''.join(f' {i}.|-- {r}\n' for i, r in enumerate(rows, 1)))


class MtrTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.tmp.name)
        awk = shlex.split(os.environ.get('EGRESS_TEST_AWK', 'awk'))
        wrapper = cls.directory / 'awk'
        # Resolve before placing the wrapper on PATH, avoiding recursion.
        import shutil
        awk[0] = shutil.which(awk[0]) or awk[0]
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.join(awk) + ' "$@"\n')
        wrapper.chmod(0o755)
        cls.env = dict(os.environ, PATH=str(cls.directory) + os.pathsep + os.environ['PATH'])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def shell(self, body, stdin=''):
        result = subprocess.run(['bash', '-c', 'set -euo pipefail\n' + CORE + '\n' + body],
                                input=stdin, text=True, capture_output=True, env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.rstrip('\n')

    def parse(self, data, target='104.18.33.45', family='-4'):
        return self.shell('parse_mtr_report ' + shlex.join([family, target]), data).split('\t')

    def test_issue_3_path(self):
        data = report(*(row(ip) for ip in [
            '172.16.0.1', '10.92.3.254', '168.95.98.254', '168.95.157.114',
            '220.128.20.86', '???', '220.128.23.145', '203.69.105.153', '104.18.33.45']))
        result = self.parse(data)
        self.assertEqual(result[0:2], ['168.95.98.254', '9.0'])
        self.assertEqual(result[2], '168.95.98.254 168.95.157.114 220.128.20.86 220.128.23.145 203.69.105.153')

    def test_only_target(self):
        self.assertEqual(self.parse(report(row('10.0.0.1'), row('104.18.33.45'))),
                         ['__HIDDEN__', '9.0', ''])

    def test_zero_latency_is_valid(self):
        self.assertEqual(self.parse(report(row('104.18.33.45', avg='0.0')))[0:2], ['__HIDDEN__', '0.0'])

    def test_all_timeouts(self):
        self.assertEqual(self.parse(report(row('???', loss='100.0', avg='0.0')))[0], '__UNCONFIRMED__')

    def test_target_full_loss_is_not_reply(self):
        self.assertEqual(self.parse(report(row('104.18.33.45', loss='100.0', avg='0.0')))[0], '__UNCONFIRMED__')

    def test_zero_packets_is_not_reply(self):
        self.assertEqual(self.parse(report(row('104.18.33.45', sent=0)))[0], '__UNCONFIRMED__')

    def test_private_only(self):
        self.assertEqual(self.parse(report(row('10.0.0.1')))[0], '__UNCONFIRMED__')

    def test_intermediate_latency_is_not_target_latency(self):
        self.assertEqual(self.parse(report(row('168.95.98.254'), row('???', loss='100')))[0:2], ['168.95.98.254', '-'])

    def test_target_not_last_statistics_row(self):
        self.assertEqual(self.parse(report(row('104.18.33.45', avg='2.0'), row('???', loss='100')))[0:2], ['__HIDDEN__', '2.0'])

    def test_unknown_destination_is_not_hidden(self):
        self.assertEqual(self.parse(report(row('104.18.33.45')), target='')[0], '__UNCONFIRMED__')

    def test_unknown_destination_with_trailing_timeouts(self):
        self.assertEqual(self.parse(report(row('104.18.33.45'), row('???', loss='100')), target='')[0], '__UNCONFIRMED__')

    def test_unknown_destination_keeps_earlier_router(self):
        self.assertEqual(self.parse(report(row('168.95.98.254'), row('104.18.33.45')), target=''), ['168.95.98.254', '-', '168.95.98.254'])

    def test_hostname_with_numeric_address(self):
        self.assertEqual(self.parse(report(row('router.example (168.95.98.254)'), row('target.example (104.18.33.45)')))[0], '168.95.98.254')

    def test_source_header_is_not_destination(self):
        data = report(row('168.95.98.254'), row('104.18.33.45')).replace('HOST: test-vps', 'HOST: source (168.95.98.254)')
        self.assertEqual(self.parse(data)[0], '168.95.98.254')

    def test_ansi_crlf(self):
        data = '\033[32m' + report(row('104.18.33.45')).replace('\n', '\033[0m\r\n')
        self.assertEqual(self.parse(data)[0], '__HIDDEN__')

    def test_bad_ipv4(self):
        for ip in ('999.1.2.3', '1.2.3', '1.2.3.4.5', '1234.1.2.3', '1..2.3', 'host.example'):
            with self.subTest(ip=ip):
                self.assertEqual(self.parse(report(row(ip), row('104.18.33.45')))[0], '__PARSE_ERROR__')

    def test_malformed_reports(self):
        for data in ('', 'mtr: permission denied', '1.|-- 8.8.8.8 broken', report(row('104.18.33.45', avg='nan')), report(row('104.18.33.45', loss='101'))):
            with self.subTest(data=data):
                self.assertEqual(self.parse(data)[0], '__PARSE_ERROR__')

    def test_private_ranges(self):
        for ip in ('10.0.0.1', '172.16.0.1', '172.31.0.1', '192.168.0.1', '100.64.0.1', '100.127.0.1', '169.254.0.1', '127.0.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255'):
            with self.subTest(ip=ip):
                self.assertEqual(self.parse(report(row(ip), row('104.18.33.45')))[0], '__HIDDEN__')

    def test_ipv6_compressed(self):
        self.assertEqual(self.parse(report(row('fe80::1'), row('2001:4860::1'), row('2606:4700::1111')), target='2606:4700::1111', family='-6'), ['2001:4860::1', '9.0', '2001:4860::1'])

    def test_ipv6_target_normalization(self):
        self.assertEqual(self.parse(report(row('2606:4700:0:0:0:0:0:ABCD')), target='2606:4700::abcd', family='-6')[0], '__HIDDEN__')

    def test_ipv6_embedded_ipv4(self):
        self.assertEqual(self.parse(report(row('::ffff:8.8.8.8')), target='::ffff:0808:0808', family='-6')[0], '__HIDDEN__')

    def test_bad_ipv6(self):
        for ip in ('2001::1::2', '2001:12345::1', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '::ffff:999.1.1.1'):
            with self.subTest(ip=ip):
                self.assertEqual(self.parse(report(row(ip)), target='2606:4700::1111', family='-6')[0], '__PARSE_ERROR__')

    def test_ipv6_private(self):
        data = report(*(row(ip) for ip in ('::', '::1', 'fe80::1', 'febf::1', 'fc00::1', 'fd00::1', 'ff02::1', '2606:4700::1111')))
        self.assertEqual(self.parse(data, target='2606:4700::1111', family='-6')[0], '__HIDDEN__')

    def probe(self, outputs, statuses=None):
        statuses = statuses or [0] * len(outputs)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for i, (data, status) in enumerate(zip(outputs, statuses), 1):
                (directory / f'{i}.txt').write_text(data)
                (directory / f'{i}.rc').write_text(str(status))
            (directory / 'calls').write_text('0')
            body = '''
is_valid_domain() { return 0; }
resolve_mtr_target() { printf 104.18.33.45; }
sleep() { :; }
run_mtr_report() {
    local n; n=$(cat "$D/calls"); n=$((n+1)); printf '%s' "$n" > "$D/calls"
    cat "$D/$n.txt"
    return "$(cat "$D/$n.rc")"
}
MTR_ATTEMPTS=2
first_public_hop -4 example.com
printf '\\n'
cat "$D/calls"
'''
            result = self.shell('D=' + shlex.quote(tmp) + '\n' + body)
            return result.splitlines()

    def test_parse_error_does_not_stop_fallback(self):
        result = self.probe(['bad report', report(row('168.95.98.254'), row('104.18.33.45'))])
        self.assertTrue(result[0].startswith('168.95.98.254\t9.0'))
        self.assertEqual(result[1], '2')

    def test_hidden_does_not_stop_retry(self):
        result = self.probe([report(row('104.18.33.45'))] * 2 + [report(row('168.95.98.254'), row('104.18.33.45'))])
        self.assertTrue(result[0].startswith('168.95.98.254'))
        self.assertEqual(result[1], '3')

    def test_hidden_is_retained_after_later_failure(self):
        result = self.probe([report(row('104.18.33.45')), '', '', ''])
        self.assertEqual(result, ['__HIDDEN__\t9.0\t', '4'])

    def test_command_failure_never_hidden(self):
        result = self.probe([report(row('104.18.33.45'))] * 4, [124] * 4)
        self.assertEqual(result[0], '__PROBE_FAILED__')

    def test_parse_error_retained(self):
        self.assertEqual(self.probe(['bad'] * 4)[0], '__PARSE_ERROR__\t-\t')

    def test_no_response_retained(self):
        self.assertEqual(self.probe([report(row('???', loss='100'))] * 4)[0], '__UNCONFIRMED__\t-\t')

    def test_markers_never_sent_to_asn_lookup(self):
        for marker in ('__HIDDEN__', '__PARSE_ERROR__', '__UNCONFIRMED__', '__PROBE_FAILED__'):
            body = 'first_public_hop() { printf %s ' + shlex.quote(marker) + '; }\n' + '''
lookup_ip() { echo unexpected_lookup >&2; exit 99; }
MTR_BASE_DOMAIN=example.com
if detect_mtr_base_asn -4 V4; then exit 42; fi
'''
            self.assertEqual(self.shell(body), '')

    def test_resolver_pins_family(self):
        body = '''
timeout() { shift; "$@"; }
getent() {
    case "$1" in
        ahostsv4) printf '104.18.33.45 STREAM example.com\\n104.18.33.45 DGRAM\\n' ;;
        ahostsv6) printf '2606:4700::1111 STREAM example.com\\n' ;;
    esac
}
ENV_TIMEOUT=5
resolve_mtr_target -4 example.com
printf '\\n'
resolve_mtr_target -6 example.com
'''
        self.assertEqual(self.shell(body).splitlines(), ['104.18.33.45', '2606:4700::1111'])

    def test_report_command_preserves_exit_status_and_stderr(self):
        body = '''
nice() { shift 2; "$@"; }
timeout() { shift; "$@"; }
mtr() { printf '%s\\n' "$*"; echo mtr_error >&2; return 7; }
MTR_TIMEOUT=1 MTR_NICE=0 MTR_COUNT=3 MTR_MAXTTL=30
rc=0
out=$(run_mtr_report -4 names 104.18.33.45 2>&1) || rc=$?
printf '%s\\n%s' "$rc" "$out"
'''
        result = self.shell(body)
        self.assertTrue(result.startswith('7\n'))
        self.assertIn('-b 104.18.33.45', result)
        self.assertIn('mtr_error', result)

    def test_output_statuses_and_counts(self):
        cases = [('__HIDDEN__\t9.0\t', 'hidden', None, '0 1'),
                 ('__PARSE_ERROR__\t-\t', 'down', 'parse_error', '1 0'),
                 ('__UNCONFIRMED__\t-\t', 'down', 'no_public_hop', '1 0'),
                 ('__PROBE_FAILED__', 'down', 'probe_failed', '1 0')]
        for marker, status, reason, counts in cases:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as tmp:
                body = function('run_check_pass') + '\n' + '''
EGRESS_BASE_MODE=auto OUTPUT_JSON=1
YELLOW= MAGENTA= RED= CYAN=
CATS=(AI); DOMAINS=(example.com); NOTES=(test)
print_pass_header() { :; }
print_category_header() { :; }
run_mtr_group() { printf '%s' "$MARKER" > "$2/0"; }
lookup_ip() { echo unexpected_lookup >&2; exit 99; }
run_check_pass IPv4 -4 "$CACHE_DIR/result.json"
cat "$CACHE_DIR/result.json"
printf '\\n%s %s' "$V4_DOWN" "$V4_HIDDEN"
'''
                prefix = 'CACHE_DIR=' + shlex.quote(tmp) + '\nMARKER=' + shlex.quote(marker) + '\n'
                output, actual_counts = self.shell(prefix + body).rsplit('\n', 1)
                result = json.loads(output)[0]
                self.assertEqual(result['status'], status)
                self.assertEqual(result.get('reason'), reason)
                self.assertEqual(result['latency_ms'], 9 if status == 'hidden' else None)
                self.assertIsNone(result['first_hop'])
                self.assertEqual(actual_counts, counts)

    def test_cli_json_terminal_and_exit_codes(self):
        cases = [
            (report(row('168.95.98.254'), row('168.95.157.114'), row('104.18.33.45')), 0, 'ok', None, '168.95.98.254'),
            (report(row('104.18.33.45')), 0, 'hidden', None, '路径隐藏 / 仅目标可见'),
            ('bad report', 0, 'down', 'parse_error', 'MTR 报告解析失败'),
            (report(row('???', loss='100')), 0, 'down', 'no_public_hop', '目标回应未确认'),
            ('mtr: permission denied', 1, 'down', 'probe_failed', '探测失败'),
        ]
        for fixture, command_rc, status, reason, message in cases:
            for output_json in (True, False):
                with self.subTest(status=status, reason=reason, json=output_json), tempfile.TemporaryDirectory() as tmp:
                    directory = Path(tmp)
                    binaries = directory / 'bin'
                    binaries.mkdir()
                    scripts = {
                        'mtr': 'cat "$MTR_FIXTURE"\nexit "$MTR_TEST_RC"\n',
                        'getent': "printf '104.18.33.45 STREAM example.com\\n'\n",
                        'curl': '''case "$*" in
  *ipinfo.io/*/json*) printf '%s' '{"country":"TW","org":"AS3462 Test ISP"}' ;;
  *) printf '168.95.98.253' ;;
esac
''',
                    }
                    for name, body in scripts.items():
                        executable = binaries / name
                        executable.write_text('#!/bin/sh\n' + body)
                        executable.chmod(0o755)
                    (directory / 'report.txt').write_text(fixture)
                    (directory / 'rules.conf').write_text('AI|example.com|||test\n')
                    env = dict(self.env, PATH=str(binaries) + os.pathsep + self.env['PATH'],
                               EGRESS_CACHE=str(directory / 'cache'), EGRESS_RULES=str(directory / 'rules.conf'),
                               MTR_FIXTURE=str(directory / 'report.txt'), MTR_TEST_RC=str(command_rc),
                               MTR_ATTEMPTS='1', MTR_CONCURRENCY='1', EGRESS_DEBUG_MTR='1')
                    args = ['bash', str(ROOT / 'ip.sh'), '-4', '--json' if output_json else '--no-color']
                    result = subprocess.run(args, text=True, capture_output=True, env=env, timeout=20)
                    self.assertEqual(result.returncode, 2 if status == 'down' else 0, result.stderr)
                    data = json.loads((directory / 'cache' / 'last.json').read_text())
                    self.assertEqual(data['ipv4']['results'][0]['status'], status)
                    self.assertEqual(data['ipv4']['results'][0].get('reason'), reason)
                    self.assertEqual(data['ipv4']['summary']['down'], int(status == 'down'))
                    if status == 'ok':
                        self.assertEqual(data['ipv4']['results'][0]['first_hop'], '168.95.98.254')
                    if output_json:
                        self.assertEqual(json.loads(result.stdout), data)
                    else:
                        self.assertIn(message, result.stdout)
                    logs = list((directory / 'cache' / 'mtr-debug').glob('*.txt'))
                    self.assertTrue(logs)
                    self.assertTrue(any(f'exit_status: {command_rc}' in log.read_text() for log in logs))


if __name__ == '__main__':
    unittest.main()
