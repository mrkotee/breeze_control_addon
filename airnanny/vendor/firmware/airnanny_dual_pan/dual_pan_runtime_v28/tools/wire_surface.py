"""Derive the RADIOV10 wire surface from the firmware, and prove it on the
real dispatcher.

Why this exists. DUAL_PAN_RADIO_PROTOCOL.md was written while the protocol was
being designed, and the firmware then shipped something different: verbs that
do not exist (CONFIG, ACK, TX, AUTO_ACCEPT as a command), an INFO that reports
`version=26 wire=10` rather than `version=10`, and an RX record whose fields
are named after `dual_format_rx` -- a formatter in src/dual_records.c that
NOTHING in the firmware calls. Four of that file's five formatters are dead,
and the document describes their vocabulary rather than the live one. A host
written from that document would not work, and the same trap cost this project
a day when the Gate A evaluator was repointed at `rx_end_us`.

So the document is no longer written by hand. This tool reads the firmware and
emits the surface as data, in two halves that are checked differently:

  commands   parsed from rejoin_transport.c, then VERIFIED against
             build/firmware_cli.exe -- the real dispatcher, the same
             translation unit the dongle runs. For every verb the exact field
             set is offered and must be accepted, and every one-field
             variation of it must be refused with reason=field_set. A parse of
             the source that disagrees with the binary loses.

  records    the printf formats the firmware emits, read from the sources that
             emit them, with each one attributed to its emitter so a dead
             formatter can never again be mistaken for the wire.

tests/test_wire_surface.py pins the document against this output, so the two
cannot drift apart again without a test failing.

    python tools/wire_surface.py            # write evidence/wire_surface.json
    python tools/wire_surface.py --print    # show it
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True

CLI = HERE / 'build/firmware_cli.exe'
FIXTURE_BOOT = '1' * 32

# A syntactically valid value per field name, so a probe is refused for its
# field SET and never for a malformed value.
VALUE = {
    'id': None,                       # supplied per probe, strictly increasing
    'boot': FIXTURE_BOOT, 'epoch': 'a' * 32, 'attempt': 'b' * 32,
    'guard': 'c' * 32, 'hash': 'd' * 64, 'mac': 'ee' * 10,
    'session': '1', 'generation': '20', 'fc': '2000', 'revision': '3',
    'dsn': '7', 'short': '4660', 'ctx': '0',
}


def source(rel):
    return (HERE / rel).read_text(encoding='utf-8')


def verbs_and_fields():
    """verbs[] and names[] exactly as rejoin_transport.c declares them."""
    src = source('src/rejoin_transport.c')
    verbs = re.search(r'const char \*verbs\[\]=\{([^}]*)\}', src).group(1)
    names = re.search(r'const char \*names\[\]=\{([^}]*)\}', src).group(1)
    unquote = lambda s: [x.strip().strip('"') for x in s.split(',')]
    return unquote(verbs), unquote(names)


def _ternary(expr, kind):
    """Evaluate the C `want` chain for one verb.

    A right-nested chain of `cond ? value : rest`, where cond is one or more
    `k==M_NAME` joined by ||, and value is an or-ed set of integer literals.
    Parsed rather than transliterated, because getting this wrong would make
    the whole table confidently incorrect -- which is the failure mode this
    tool exists to prevent, so it is also verified against the binary below.
    """
    expr = expr.strip()
    while True:
        m = re.match(r'^(.*?)\?(.*)$', expr, re.S)
        if not m:
            return eval(expr, {'__builtins__': {}}, {})     # the final default
        cond, rest = m.group(1), m.group(2)
        depth, cut = 0, None
        for i, ch in enumerate(rest):
            if ch == '?':
                depth += 1
            elif ch == ':':
                if depth == 0:
                    cut = i
                    break
                depth -= 1
        value, expr = rest[:cut], rest[cut + 1:]
        if any(c.strip() == 'k==%s' % kind for c in cond.split('||')):
            return eval(value, {'__builtins__': {}}, {})


def declared_field_sets():
    """Each verb's field set, as the source declares it."""
    verbs, names = verbs_and_fields()
    src = source('src/rejoin_transport.c')
    want = re.search(r'unsigned want=(.*?);\s*\n', src, re.S).group(1)
    kinds = re.search(r'\}\s*management_kind_t', source('include/management.h'))
    enum = re.search(r'typedef enum \{([^}]*)\}', source('include/management.h'))
    order = [x.strip() for x in enum.group(1).split(',')]
    assert len(order) == len(verbs), (len(order), len(verbs))

    out = {}
    for verb, kind in zip(verbs, order):
        mask = _ternary(want, kind)
        fields = sorted(names[i] for i in range(len(names)) if mask & (1 << i))
        # ctx is decided by scope rather than by the mask; see the block after
        # `want` in rejoin_transport.c.
        if kind in ('M_INFO', 'M_END', 'M_STATS'):
            ctx = 'refused'
        elif kind == 'M_STATUS':
            ctx = 'optional'
        else:
            ctx = 'required'
        fields = [f for f in fields if f != 'ctx']
        out[verb] = {'kind': kind, 'fields': fields, 'ctx': ctx}
    return out, names


class Dispatcher:
    """The real C dispatcher, one process, ids strictly increasing."""

    def __init__(self):
        if not CLI.exists():
            raise SystemExit('run tests/run_native.sh first to build %s' % CLI)
        self.p = subprocess.Popen([str(CLI)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True)
        self.id = 0

    def ask(self, verb, fields, ctx=None):
        self.id += 1
        parts = ['RADIOV10', verb, 'id=%d' % self.id]
        for f in fields:
            if f == 'id':
                continue
            parts.append('%s=%s' % (f, VALUE[f]))
        if ctx is not None:
            parts.append('ctx=%s' % ctx)
        self.p.stdin.write(' '.join(parts) + '\n')
        self.p.stdin.flush()
        reasons = []
        while True:
            line = self.p.stdout.readline()
            if not line or line.startswith('@END'):
                break
            m = re.search(r'\breason=(\S+)', line)
            if m and ' ERROR ' in line:
                reasons.append(m.group(1))
        return reasons[0] if reasons else None

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=5)
            self.p.stdout.close()
        except Exception:
            pass


def verify(declared, names):
    """Offer each declared set to the binary, then every one-field variation.

    The declared set must NOT be refused for its field set -- it may well be
    refused for state, which is a different question and not this one. Every
    variation must be refused with exactly field_set. A source parse that the
    binary disagrees with is wrong, and this says which verb and which field.
    """
    d = Dispatcher()
    try:
        report = {}
        for verb, spec in declared.items():
            ctx = {'required': '0', 'optional': None, 'refused': None}[spec['ctx']]
            exact = d.ask(verb, spec['fields'], ctx)
            variations = {}
            for f in names:
                if f == 'ctx':
                    continue
                if f in spec['fields']:
                    alt = [x for x in spec['fields'] if x != f]
                    if 'id' not in alt:            # id is always carried
                        continue
                    variations['without:' + f] = d.ask(verb, alt, ctx)
                else:
                    variations['with:' + f] = d.ask(verb, spec['fields'] + [f], ctx)
            bad = {k: v for k, v in variations.items() if v != 'field_set'}
            report[verb] = {
                'exact_set_refused_for_its_fields': exact == 'field_set',
                'exact_set_reply': exact,
                'variations_not_refused_as_field_set': bad,
                'agrees_with_binary': exact != 'field_set' and not bad,
            }
            if spec['ctx'] == 'required':
                report[verb]['without_ctx'] = d.ask(verb, spec['fields'])
            if spec['ctx'] == 'refused':
                report[verb]['with_ctx'] = d.ask(verb, spec['fields'], '0')
            if spec['ctx'] == 'optional':
                report[verb]['without_ctx'] = d.ask(verb, spec['fields'])
                report[verb]['with_ctx'] = d.ask(verb, spec['fields'], '0')
        return report
    finally:
        d.close()


RECORD_SOURCES = [
    ('src/main.c', 'RADIO_PREFIX', True),
    ('src/tx_lifecycle.inc', 'RADIO_PREFIX', True),
    ('src/dual_records.c', 'RADIOV10_PREFIX', None),   # live-ness decided below
]


def records():
    """Every record the firmware can print, with its emitter and whether that
    emitter is reachable. The dead ones are listed rather than omitted: they
    are the reason this tool exists, and a reader who finds them in the source
    needs to be told they are not the wire."""
    out = {}
    for rel, prefix, live in RECORD_SOURCES:
        src = source(rel)
        for m in re.finditer(re.escape(prefix) + r' " ([A-Z_%][^"]*)"', src):
            body = m.group(1)
            kind = body.split()[0]
            fields = re.findall(r'(\w+)=', body)
            entry = {'kind': kind, 'emitter': rel,
                     'fields': [f for f in fields if f != kind],
                     'format': body.rstrip('\\n')}
            if kind == '%s':                     # TXDONE / AUTO_DONE share one
                entry['kind'] = 'TXDONE|AUTO_DONE'
                kind = entry['kind']
            out.setdefault(kind, []).append(entry)

    # dual_records.c: only the formatter main.c calls is on the wire.
    called = source('src/main.c') + source('src/tx_lifecycle.inc')
    for kind, entries in out.items():
        for e in entries:
            if e['emitter'] != 'src/dual_records.c':
                e['live'] = True
                continue
            fn = {'STATS': 'dual_format_stats', 'RX': 'dual_format_rx',
                  'ERROR': 'dual_format_error', 'TXACCEPT': 'dual_format_txaccept',
                  'TXDONE': 'dual_format_txdone',
                  'TXDONE|AUTO_DONE': 'dual_format_txdone'}.get(kind)
            e['live'] = bool(fn and fn in called)
            e['formatter'] = fn
    return out


def surface():
    declared, names = declared_field_sets()
    verification = verify(declared, names)
    recs = records()
    dead = sorted({e['formatter'] for v in recs.values() for e in v
                   if not e['live'] and e.get('formatter')})
    return {
        'record': 'wire_surface',
        'identity': 'airnanny_dual_pan_runtime_v28',
        'wire': re.search(r'#define RADIO_WIRE_VERSION (\d+)',
                          source('include/radio_wire.h')).group(1),
        'firmware_version': re.search(r'version=(\d+)',
                                      source('src/main.c')).group(1),
        'field_names_in_order': names,
        'commands': declared,
        'verified_against_dispatcher': verification,
        'commands_agree_with_binary': all(
            v['agrees_with_binary'] for v in verification.values()),
        'records': recs,
        'dead_formatters_not_on_the_wire': dead,
        'note': ('commands are parsed from rejoin_transport.c and then proven '
                 'against build/firmware_cli.exe; records are read from the '
                 'sources that emit them, with dead formatters marked rather '
                 'than hidden.'),
    }


COMMANDS_MARK = 'wire-surface:commands'
# V28's records differ from V27's by one TXDONE field, and V27's tree still
# checks the shared document against its own table, so V28 has its own block.
RECORDS_MARK = 'wire-surface:records-v28'


def render(s, mark):
    """The markdown the protocol document carries between its markers.

    Generated rather than written, so the document cannot drift from the
    firmware again: tests/test_wire_surface.py re-renders this and compares.
    """
    L = []
    if mark == COMMANDS_MARK:
        L.append('| Verb | `ctx` | Поля (помимо `ctx`) |')
        L.append('| --- | --- | --- |')
        for verb, spec in s['commands'].items():
            L.append('| `%s` | %s | %s |'
                     % (verb, {'required': '**обязателен**',
                               'optional': 'необязателен',
                               'refused': 'отвергается'}[spec['ctx']],
                        ' '.join('`%s`' % f for f in spec['fields'])))
    else:
        L.append('| Запись | Эмиттер | На проводе | Поля |')
        L.append('| --- | --- | --- | --- |')
        for kind in sorted(s['records']):
            for e in s['records'][kind]:
                L.append('| `%s` | `%s` | %s | %s |'
                         % (e['kind'], e['emitter'],
                            'да' if e['live'] else '**нет, мёртвый код**',
                            ' '.join('`%s`' % f for f in e['fields'])))
    return '\n'.join(L)


def splice(path, s):
    """Replace each marked block in the document with freshly rendered text."""
    text = Path(path).read_text(encoding='utf-8')
    for mark in (COMMANDS_MARK, RECORDS_MARK):
        pattern = re.compile(r'(<!-- %s -->\n)(.*?)(<!-- /%s -->)'
                             % (re.escape(mark), re.escape(mark)), re.S)
        if not pattern.search(text):
            raise SystemExit('document has no %s block' % mark)
        text = pattern.sub(
            lambda m: m.group(1) + render(s, mark) + '\n' + m.group(3), text)
    Path(path).write_text(text, encoding='utf-8')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--print', action='store_true', dest='show')
    ap.add_argument('--doc', metavar='PATH',
                    help='splice the generated tables into this document')
    args = ap.parse_args()
    s = surface()
    if args.doc:
        splice(args.doc, s)
        print('spliced %s' % args.doc)
    if args.show:
        print(json.dumps(s, indent=2, ensure_ascii=False))
    else:
        p = HERE / 'evidence/wire_surface.json'
        p.write_text(json.dumps(s, indent=2, ensure_ascii=False) + '\n',
                     encoding='utf-8')
        print('wrote %s' % p)
    if not s['commands_agree_with_binary']:
        print('\nREFUSED: the parsed command table disagrees with the real '
              'dispatcher:', file=sys.stderr)
        for verb, v in s['verified_against_dispatcher'].items():
            if not v['agrees_with_binary']:
                print('  %-34s %r' % (verb, v), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
