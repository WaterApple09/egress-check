"""Offline regression tests: no DNS, MTR packets, installs, or API requests.

Run with python3 -m unittest discover -s tests -v.
EGRESS_TEST_AWK can select gawk, mawk, or 'busybox awk'.
"""
import os
import json
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'ip.sh').read_text()


def function(name):
    start = SOURCE.index(name + '() {')
    first_line = SOURCE[start:SOURCE.index('\n', start)]
    if first_line.endswith('}'):
        return first_line
    end = SOURCE.index('\n}', start) + 2
    return SOURCE[start:end]


CORE = '\n'.join(function(n) for n in (
    'run_mtr_report', 'resolve_mtr_target', 'parse_mtr_report',
    'first_public_hop', 'detect_mtr_base_asn', 'split_tsv4',
    'is_valid_domain', 'tcp_connect_latency', 'probe_domain'))


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
        result = subprocess.run(['bash', '-c', 'set -euo pipefail\nMTR_TIMEOUT=20 MTR_TOTAL_TIMEOUT=12 MTR_ATTEMPTS=2 LATENCY_TIMEOUT=3 ENV_TIMEOUT=5 MTR_AVAILABLE=1 SYM_DOWN=X SYM_SKIP=-\n' + CORE + '\n' + body],
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

    def test_parse_error_stops_immediately(self):
        self.assertEqual(self.probe(['bad report']), ['__PARSE_ERROR__\t-\t', '1'])

    def test_hidden_stops_immediately(self):
        self.assertEqual(self.probe([report(row('104.18.33.45'))]), ['__HIDDEN__\t9.0\t', '1'])

    def test_unconfirmed_can_retry_once(self):
        result = self.probe([report(row('???', loss='100')), report(row('168.95.98.254'), row('104.18.33.45'))])
        self.assertTrue(result[0].startswith('168.95.98.254\t9.0'))
        self.assertEqual(result[1], '2')

    def test_command_failure_never_hidden(self):
        result = self.probe([report(row('104.18.33.45'))] * 2, [124] * 2)
        self.assertEqual(result, ['__PROBE_FAILED__\t-\t', '2'])

    def test_command_failure_stops_immediately(self):
        result = self.probe(['mtr failed'], [1])
        self.assertEqual(result, ['__PROBE_FAILED__\t-\t', '1'])

    def test_permission_failure_stops_immediately(self):
        result = self.probe(['mtr: Operation not permitted'], [1])
        self.assertEqual(result, ['__MTR_UNAVAILABLE__\t-\t', '1'])

    def test_no_response_retained(self):
        self.assertEqual(self.probe([report(row('???', loss='100'))] * 2), ['__UNCONFIRMED__\t-\t', '2'])

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
timeout() { if [[ "$1" == -k ]]; then shift 2; fi; shift; "$@"; }
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
timeout() { if [[ "$1" == -k ]]; then shift 2; fi; shift; "$@"; }
mtr() { printf '%s\\n' "$*"; echo mtr_error >&2; return 7; }
MTR_TIMEOUT=1 MTR_NICE=0 MTR_COUNT=3 MTR_MAXTTL=30
rc=0
out=$(run_mtr_report -4 104.18.33.45 2>&1) || rc=$?
printf '%s\\n%s' "$rc" "$out"
'''
        result = self.shell(body)
        self.assertTrue(result.startswith('7\n'))
        self.assertIn('-n', result)
        self.assertNotIn('-b', result)
        self.assertIn('104.18.33.45', result)
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
            ('mtr: permission denied', 1, 'down', 'mtr_unavailable', 'MTR 不可用'),
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

    def test_tcp_timing_excludes_dns_even_after_tls_failure(self):
        body = '''
timeout() { shift 3; "$@"; }
curl() {
    [[ "$1" == -q ]] || exit 90
    [[ "$*" == *"--noproxy *"* && "$*" == *"--proxy "* && "$*" == *"-6"* ]] || exit 91
    printf '0.060000\\t0.010000'
    return 60
}
tcp_connect_latency -6 example.com
'''
        self.assertEqual(self.shell(body), '50.0')

    def test_tcp_failure_has_no_fabricated_zero(self):
        for timings in ('0.000000\t0.010000', '0.000000\t0.000000', '', 'bad timing', '0.01\t0.02'):
            body = 'TIMINGS=' + shlex.quote(timings) + '\n' + '''
timeout() { shift 3; "$@"; }
curl() { printf '%s' "$TIMINGS"; return 7; }
tcp_connect_latency -4 example.com
'''
            with self.subTest(timings=timings):
                self.assertEqual(self.shell(body), '')

    def test_real_tcp_connection_survives_tls_failure(self):
        # Real curl against a local socket: no public network or raw-socket
        # permissions. The peer deliberately cannot complete a TLS handshake.
        with socket.socket() as server, tempfile.TemporaryDirectory() as tmp:
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            server.settimeout(5)
            port = server.getsockname()[1]
            def reply():
                try:
                    connection, _ = server.accept()
                    with connection:
                        connection.sendall(b'HTTP/1.0 400 Bad Request\r\n\r\n')
                except OSError:
                    pass
            worker = threading.Thread(target=reply, daemon=True)
            worker.start()
            executable = Path(tmp) / 'curl'
            actual_curl = shutil.which('curl')
            self.assertIsNotNone(actual_curl)
            executable.write_text('#!/bin/sh\nexec ' + shlex.quote(actual_curl)
                                  + ' "$@" --connect-to example.com:443:127.0.0.1:' + str(port) + '\n')
            executable.chmod(0o755)
            body = 'PATH=' + shlex.quote(tmp) + ':"$PATH"\ntcp_connect_latency -4 example.com'
            latency = self.shell(body)
            self.assertNotEqual(latency, '')
            self.assertGreaterEqual(float(latency), 0)
            worker.join(timeout=5)

    def test_fallback_keeps_route_and_source_fields_separate(self):
        body = '''
first_public_hop() { printf '168.95.98.254\\t-\\t168.95.98.254 168.95.157.114'; }
tcp_connect_latency() { printf 50.0; }
probe_domain -4 example.com
'''
        self.assertEqual(self.shell(body), '168.95.98.254\t50.0\t168.95.98.254 168.95.157.114\ttcp_connect')

    def test_fallback_keeps_empty_path_field(self):
        body = '''
first_public_hop() { printf '__MTR_UNAVAILABLE__\\t-\\t'; }
tcp_connect_latency() { printf 50.0; }
probe_domain -4 example.com
'''
        self.assertEqual(self.shell(body), '__MTR_UNAVAILABLE__\t50.0\t\ttcp_connect')

    def test_verified_mtr_latency_needs_no_extra_connection(self):
        body = '''
first_public_hop() { printf '__HIDDEN__\\t9.0\\t'; }
tcp_connect_latency() { exit 90; }
probe_domain -4 example.com
'''
        self.assertEqual(self.shell(body), '__HIDDEN__\t9.0\t\tmtr')

    def test_unavailable_mtr_needs_no_dns_or_probe(self):
        body = '''
MTR_AVAILABLE=0
resolve_mtr_target() { exit 90; }
run_mtr_report() { exit 91; }
first_public_hop -4 example.com
'''
        self.assertEqual(self.shell(body), '__MTR_UNAVAILABLE__\t-\t')

    def test_runtime_failure_disables_only_affected_family(self):
        body = '''
first_public_hop() { printf '__MTR_UNAVAILABLE__\\t-\\t'; }
err() { :; }
MTR_BASE_DOMAIN=example.com
detect_mtr_base_asn -4 V4 || true
printf '%s %s %s' "$V4_MTR_AVAILABLE" "${V6_MTR_AVAILABLE:-1}" "$MTR_AVAILABLE"
'''
        self.assertEqual(self.shell(body), '0 1 1')

    def test_mtr_total_budget_caps_a_hung_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / 'mtr'
            executable.write_text('#!/bin/sh\nsleep 30\n')
            executable.chmod(0o755)
            body = 'PATH=' + shlex.quote(tmp) + ':"$PATH"\n' + '''
MTR_TOTAL_TIMEOUT=1 MTR_ATTEMPTS=50 MTR_COUNT=3 MTR_MAXTTL=30 MTR_NICE=0
resolve_mtr_target() { printf 104.18.33.45; }
first_public_hop -4 example.com
'''
            started = time.monotonic()
            self.assertEqual(self.shell(body), '__PROBE_FAILED__\t-\t')
            self.assertLess(time.monotonic() - started, 4)

    def test_resolution_consumes_the_same_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / 'getent'
            executable.write_text('#!/bin/sh\nsleep 30\n')
            executable.chmod(0o755)
            body = 'PATH=' + shlex.quote(tmp) + ':"$PATH"\n' + '''
MTR_TOTAL_TIMEOUT=1 MTR_ATTEMPTS=50
run_mtr_report() { echo should_not_run >&2; exit 91; }
first_public_hop -4 example.com
'''
            started = time.monotonic()
            self.assertEqual(self.shell(body), '__PROBE_FAILED__\t-\t')
            self.assertLess(time.monotonic() - started, 4)

    def test_cli_retains_latency_when_route_is_unavailable(self):
        cases = [
            ('missing', '', 0, 'partial', 'mtr_unavailable', '50.0', 0),
            ('permission', 'mtr: Operation not permitted', 1, 'partial', 'mtr_unavailable', '50.0', 60),
            ('parse', 'bad report', 0, 'partial', 'parse_error', '50.0', 0),
            ('hidden_path', report(row('???', loss='100')), 0, 'partial', 'no_public_hop', '50.0', 0),
            ('command', 'mtr: failed', 1, 'partial', 'probe_failed', '50.0', 0),
            ('no_target_reply', report(row('168.95.98.254'), row('???', loss='100')), 0, 'ok', None, '50.0', 0),
            ('both_failed', 'mtr: failed', 1, 'down', 'probe_failed', None, 7),
        ]
        for mode, fixture, mtr_rc, status, reason, latency, curl_rc in cases:
            for output_json in (True, False):
                with self.subTest(mode=mode, json=output_json), tempfile.TemporaryDirectory() as tmp:
                    directory = Path(tmp)
                    binaries = directory / 'bin'
                    binaries.mkdir()
                    # Simulate command discovery on a host without mtr, even if
                    # the CI image happens to have mtr installed globally.
                    (directory / 'startup.sh').write_text('''command() {
  if [[ "$1" == -v && "$2" == mtr && "$TEST_MODE" == missing ]]; then return 1; fi
  builtin command "$@"
}
''')
                    scripts = {
                        'mtr': 'echo call >> "$TEST_DIR/mtr-calls"\ncat "$TEST_DIR/report"\nexit "$TEST_MTR_RC"\n',
                        'getent': "printf '104.18.33.45 STREAM example.com\\n'\n",
                        'apt-get': 'echo unexpected_install >&2; exit 99\n',
                        'curl': '''case "$*" in
  *--write-out*)
    echo call >> "$TEST_DIR/tcp-calls"
    if [ "$TEST_MODE" = both_failed ]; then printf '0.000000\\t0.010000';
    else printf '0.060000\\t0.010000'; fi
    exit "$TEST_CURL_RC" ;;
  *ipinfo.io/*/json*) printf '%s' '{"country":"TW","org":"AS3462 Test ISP"}' ;;
  *) printf '168.95.98.253' ;;
esac
''',
                    }
                    for name, body in scripts.items():
                        executable = binaries / name
                        executable.write_text('#!/bin/sh\n' + body)
                        executable.chmod(0o755)
                    (directory / 'report').write_text(fixture)
                    (directory / 'rules').write_text('AI|example.com|||test\nAI|example.org|||test\n')
                    env = dict(self.env, PATH=str(binaries) + os.pathsep + self.env['PATH'],
                               BASH_ENV=str(directory / 'startup.sh'), TEST_DIR=tmp, TEST_MODE=mode,
                               TEST_MTR_RC=str(mtr_rc), TEST_CURL_RC=str(curl_rc),
                               EGRESS_CACHE=str(directory / 'cache'), EGRESS_RULES=str(directory / 'rules'),
                               MTR_ATTEMPTS='2', MTR_CONCURRENCY='2')
                    args = ['bash', str(ROOT / 'ip.sh'), '-4', '--json' if output_json else '--no-color']
                    result = subprocess.run(args, text=True, capture_output=True, env=env, timeout=20)
                    self.assertEqual(result.returncode, 0 if status == 'ok' else 2, result.stderr)
                    data = json.loads((directory / 'cache' / 'last.json').read_text())
                    for item in data['ipv4']['results']:
                        self.assertEqual(item['status'], status)
                        self.assertEqual(item.get('reason'), reason)
                        self.assertEqual(item['latency_ms'], float(latency) if latency else None)
                        self.assertEqual(item['latency_source'], 'tcp_connect' if latency else None)
                        self.assertEqual(item['latency_port'], 443 if latency else None)
                        if status != 'ok':
                            self.assertIsNone(item['first_hop'])
                            self.assertIsNone(item['asn'])
                            self.assertIsNone(item['split'])
                    summary = data['ipv4']['summary']
                    self.assertEqual(summary[status], 2)
                    self.assertEqual(summary['total'], 2)
                    self.assertEqual(len((directory / 'tcp-calls').read_text().splitlines()), 2)
                    if mode == 'missing':
                        self.assertFalse((directory / 'mtr-calls').exists())
                    if mode == 'permission':
                        self.assertEqual(len((directory / 'mtr-calls').read_text().splitlines()), 1)
                    if output_json:
                        self.assertEqual(json.loads(result.stdout), data)
                    elif latency:
                        self.assertIn('50.0ms TCP', result.stdout)
                        if status == 'partial':
                            self.assertIn('仅连接延迟，路径不可用', result.stdout)


if __name__ == '__main__':
    unittest.main()
