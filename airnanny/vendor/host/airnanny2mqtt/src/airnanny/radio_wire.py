"""The shipped V28 RADIOV10 surface, extracted from reviewed firmware evidence."""
import re
from .serial_support import SerialFault
from .radio_surface import SURFACE

HEX32 = re.compile(r'[0-9a-f]{32}\Z')


def number(fields, name, maximum=0xffffffff):
    value = fields.get(name, '')
    if not re.fullmatch(r'[0-9]{1,10}', value) or int(value) > maximum:
        raise SerialFault('radio_invalid_number:' + name)
    return int(value)


def mac_bytes(value):
    if not re.fullmatch(r'(?:[0-9a-f]{2}){1,125}', value):
        raise SerialFault('radio_invalid_mac')
    return bytes.fromhex(value)


def parse_record(line):
    try:
        tokens = line.decode('ascii').split(' ')
        if len(tokens) < 3 or tokens[0] != 'RADIOV10':
            raise ValueError()
        kind, fields = tokens[1], {}
        for token in tokens[2:]:
            key, value = token.split('=', 1)
            if not re.fullmatch(r'[a-z][a-z0-9_]*', key) or not value or key in fields:
                raise ValueError()
            fields[key] = value
        schemas = SURFACE['records'].get('TXDONE|AUTO_DONE' if kind in ('TXDONE', 'AUTO_DONE') else kind)
        if not schemas or not any(set(fields) == set(s) for s in schemas):
            # STATS formatter's adjacent C strings add numeric diagnostics
            # omitted by the upstream surface extractor. No decisions use extras.
            v33_status=(kind=='STATUS' and schemas and any(
                set(fields)==set(s)|{'config_generation','late_join_restartable'} for s in schemas))
            if not v33_status and (kind != 'STATS' or not schemas or not set(schemas[0]) <= set(fields)):
                raise ValueError()
            for k in set(fields) - set(schemas[0]):
                number(fields, k)
        if not HEX32.fullmatch(fields['boot']):
            raise ValueError()
        return kind, fields
    except (ValueError, KeyError, UnicodeError):
        raise SerialFault('radio_malformed_record') from None


def command(verb, identifier, *, boot=None, ctx=None, **fields):
    spec = SURFACE['commands'].get(verb)
    if spec is None or type(identifier) is not int or not 0 < identifier <= 0xffffffff:
        raise ValueError('radio command identity')
    values = dict(id=str(identifier))
    if boot is not None:
        if not HEX32.fullmatch(boot):
            raise ValueError('radio boot token')
        values['boot'] = boot
    values.update({k: str(v) for k, v in fields.items()})
    if set(values) != set(spec['fields']):
        raise ValueError('radio command field set')
    if spec['ctx'] == 'required' and (type(ctx) is not int or ctx not in (0, 1)):
        raise ValueError('radio command context required')
    if ctx is not None:
        if spec['ctx'] == 'refused' or type(ctx) is not int or ctx not in (0, 1):
            raise ValueError('radio command context refused')
        values['ctx'] = str(ctx)
    if any(not re.fullmatch(r'[A-Za-z0-9_.-]+', value) for value in values.values()):
        raise ValueError('radio command token')
    return ('RADIOV10 ' + verb + ' ' + ' '.join(k + '=' + v for k, v in values.items())).encode('ascii')
