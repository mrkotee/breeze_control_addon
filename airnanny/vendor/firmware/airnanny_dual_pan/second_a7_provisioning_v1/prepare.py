"""Offline ctx1 preparation. No serial import, device enumeration or RF.

Frozen ctx0 files are only read. The generated commissioning sources differ
only in target binding and the fresh-identity seed admission (not protocol).
"""
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'raw_radio_v7_assoc_poll_cca'
REPO = ROOT.parents[2]
CTX0_RAW = 'e2b0275f4d582069'
TC = '00124b0036a1875f'


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


identity_store = load_module('second_a7_identity_store', ROOT.parent / 'raw_radio_v4_assoc_permit/tools/identity_store.py')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def protected_inventory():
    result = {}
    for directory in ROOT.parent.iterdir():
        if not directory.is_dir() or directory == ROOT:
            continue
        for path in (directory / '.local').rglob('*'):
            if path.is_file() and not any(x in path.parts for x in ('__pycache__', 'zig-global', 'zig-local')):
                try:
                    result[path.relative_to(REPO).as_posix()] = sha(path)
                except PermissionError:
                    raise RuntimeError('protected_inventory_unreadable:' + str(path.relative_to(REPO)))
    return result


def forbidden_inventory():
    seed = json.loads((ROOT.parent / 'raw_radio_v4_assoc_permit/.local/hardware_v1/ctx0.json').read_text())
    forbidden = set(seed['forbidden_inventory']) | {CTX0_RAW, TC}
    # Conservative exclusion of every individually addressed IEEE-sized value
    # in earlier textual sources/evidence, including prior synthetic identities.
    # Only the set digest/count is public: arbitrary matches may be private data.
    for directory in ROOT.parent.iterdir():
        if not directory.is_dir() or directory == ROOT:
            continue
        for path in directory.rglob('*'):
            if not path.is_file() or path.suffix not in ('.json', '.py', '.md', '.c', '.h'):
                continue
            if any(x in path.parts for x in ('radio_driver', 'build', '__pycache__', 'zig-global', 'zig-local')):
                continue
            value = path.read_text(encoding='utf-8', errors='replace')
            for token in re.findall(r'(?<![0-9a-fA-F])[0-9a-fA-F]{16}(?![0-9a-fA-F])', value):
                token = token.lower()
                try:
                    identity_store.wire(token)
                except ValueError:
                    continue
                forbidden.add(token)
    return forbidden


def replace_exact(text, old, new):
    if old not in text:
        raise RuntimeError('frozen_source_shape_changed:' + old)
    return text.replace(old, new)


def specialize(text, raw):
    replacements = {
        CTX0_RAW: raw, '00124b0036a148e5': TC,
        '0xfa9b': '0x0b7a', 'pan=fa9b': 'pan=0b7a', 'target_pan=fa9b': 'target_pan=0b7a',
        'ctx=0': 'ctx=1', 'ctx!=0': 'ctx!=1', 'ctx != 0': 'ctx != 1',
        'ctx==0': 'ctx==1', "'ctx':0": "'ctx':1", 'ctx not in (0,1)': 'ctx != 1',
        'Rx(0,': 'Rx(1,',
        r'\x9b\xfa': r'\x7a\x0b',
        "r['ctx']!=0": "r['ctx']!=1",
        'ctx0/FA9B': 'ctx1/0B7A',
        '9bfab7c9': '7a0bb7c9', '9bfaffff': '7a0bffff', '63cc939bfa': '63cc937a0b',
        '0x69,0x20,0x58,0x4d,0x5f,0x27,0xb0,0xe2': ','.join('0x%02x' % b for b in bytes.fromhex(raw)[::-1]),
        '0xe5,0x48,0xa1,0x36,0,0x4b,0x12,0': '0x5f,0x87,0xa1,0x36,0,0x4b,0x12,0',
        'airnanny_raw_assoc_poll_cca_v7_prep': 'airnanny_ctx1_commission_v7',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def materialize(record):
    raw = record['raw_ieee']
    provenance = {}
    # Radio driver remains the exact read-only V7 driver; build paths refer to it.
    files = list((BASE/'src').glob('*')) + list((BASE/'include').glob('*'))
    files += [BASE/p for p in ('host/core.py', 'host/single_boot.py', 'host/current_a7_baseline.py',
                               'tools/key_announce.py', 'tools/build.py', 'tools/native_build.py')]
    files += list((BASE/'tests').rglob('*'))
    for source in files:
        if not source.is_file() or source.suffix not in ('.py', '.c', '.h', '.ld', '.inc'):
            continue
        relative = source.relative_to(BASE)
        if relative.parts[0] == 'tests' and source.suffix == '.py' and source.name != 'test_single_boot.py':
            continue
        output = ROOT / relative
        text = specialize(source.read_text(encoding='utf-8'), raw)
        if relative.as_posix() == 'host/core.py':
            text = text.replace('class Stop(RuntimeError):pass', 'from bindings import OwnedSecret\nclass Stop(RuntimeError):pass')
            text = replace_exact(text, "self.c=provision.context();self.root=Path(root)",
                                 "if not isinstance(tc_key,OwnedSecret):raise Stop('ctx1_TC_candidate_provenance_required')\n        tc_key.require('tc_link')\n        self.c=provision.context();self.root=Path(root)")
            text = text.replace('self.c.generation,0,RAW', 'self.c.generation,1,RAW')
            text = text.replace("r['generation'],0,RAW", "r['generation'],1,RAW")
            text = text.replace('Rx(0,', 'Rx(1,')
            text = replace_exact(text, "seed.get('state')!='ASSOCIATED_UNKEYED'", "seed.get('state')!='ALLOCATED_UNUSED'")
            text = replace_exact(text, "seed.get('generation')!=2", "seed.get('generation')!=0")
            text = replace_exact(text, "seed.get('attempt')!=OLD_ATTEMPT", "seed.get('attempt') is not None")
            text = replace_exact(text, "seed.get('ctx')!=0", "seed.get('ctx')!=1")
            text = replace_exact(text, "previous_attempt=OLD_ATTEMPT,previous_generation=2,previous_short=seed['assigned_short']", "previous_attempt=None,previous_generation=0,previous_short=None")
        if relative.as_posix() == 'host/single_boot.py':
            text = text.replace('generation=3,revision_floor=', 'generation=3,ctx=1,revision_floor=')
            text = text.replace('from core import *', 'from core import *\nfrom bindings import OwnedSecret')
            text = replace_exact(text, "self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True)",
                                 "if not isinstance(tc_key,OwnedSecret) or not isinstance(permit_key,OwnedSecret):raise Stop('explicit_ctx1_secret_provenance_required')\n        tc_key.require('tc_link');permit_key.require('permit_candidate')\n        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True)")
            text = text.replace("key_epoch='explicit_protected_current_network'", "key_epoch=self.permit_key.epoch")
        if relative.as_posix() == 'tests/test_single_boot.py':
            text = text.replace("'state':'ASSOCIATED_UNKEYED','generation':2,'attempt':OLD_ATTEMPT", "'state':'ALLOCATED_UNUSED','generation':0,'attempt':None")
            text = text.replace('Rx(0,', 'Rx(1,')
            text = text.replace('from key_announce import encrypt', 'from bindings import OwnedSecret\nfrom key_announce import encrypt')
            text = text.replace('self.tc=Secret(bytes(range(16)));self.nk=Secret(bytes(range(16,32)))',
                                "self.tc=OwnedSecret(1,0x0b7a,TC,'tc_link','synthetic-ctx1-tc',bytes(range(16)));self.nk=OwnedSecret(1,0x0b7a,TC,'permit_candidate','synthetic-ctx1-candidate',bytes(range(16,32)))")
        if relative.as_posix() == 'tools/key_announce.py':
            text = replace_exact(text, "self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.path=self.root/'epoch.json';self.secrets=secrets_backend",
                                 "self.root=Path(root).resolve()\n        if not self.root.is_relative_to((ROOT/'.local').resolve()) or not Path(secrets_backend.root).resolve().is_relative_to((ROOT/'.local').resolve()):raise ValueError('ctx1_separate_security_storage_required')\n        self.root.mkdir(parents=True,exist_ok=True);self.path=self.root/'epoch.json';self.secrets=secrets_backend")
            text = replace_exact(text, "if self.raw_ieee==self.tc_ieee:raise ValueError('identity owner')",
                                 "if self.raw_ieee!='" + raw + "' or self.tc_ieee!='" + TC + "' or self.extpan!=self.tc_ieee:raise ValueError('ctx1 identity owner')")
            text = replace_exact(text, "def read(self):return json.loads(self.path.read_text(encoding='utf-8'))", """def read(self):
        r=json.loads(self.path.read_text(encoding='utf-8'))
        Context(**r['context'])
        anchor=json.loads((self.root/'context_anchor.json').read_text(encoding='utf-8'))
        if r['context']!=anchor or r['generation'] not in (anchor['generation'],anchor['generation']+1,anchor['generation']+2):raise ValueError('ctx1 epoch lineage')
        authority_path=self.root/'epoch_anchor.json'
        if authority_path.exists():
            authority=json.loads(authority_path.read_text(encoding='utf-8'))
            if authority!={k:r.get(k) for k in ('context','key_epoch_id','secret_ref','keyseq')}:raise ValueError('ctx1 security epoch owner')
        elif 'key_epoch_id' in r:raise ValueError('missing independent ctx1 epoch anchor')
        return r""")
            text = replace_exact(text, "if self.path.exists():raise ValueError('never overwrite security epoch')",
                                 "if self.path.exists() or (self.root/'context_anchor.json').exists():raise ValueError('never overwrite security epoch')\n            Context(**c.__dict__)\n            durable(self.root/'context_anchor.json',c.__dict__)")
            text = replace_exact(text, "durable(self.path,r)\n            if fail=='secret'", "durable(self.root/'epoch_anchor.json',{k:r[k] for k in ('context','key_epoch_id','secret_ref','keyseq')})\n            durable(self.path,r)\n            if fail=='secret'")
        if relative.as_posix() == 'tools/build.py':
            text = text.replace("ROOT/'radio_driver", "ROOT.parent/'raw_radio_v7_assoc_poll_cca/radio_driver")
            text = text.replace("(ROOT/'radio_driver')", "(ROOT.parent/'raw_radio_v7_assoc_poll_cca/radio_driver')")
        if relative.as_posix() == 'tools/native_build.py':
            text = text.replace("'-Iradio_driver'", "'-I../raw_radio_v7_assoc_poll_cca/radio_driver'")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding='utf-8', newline='\n')
        provenance[relative.as_posix()] = {'source': source.relative_to(REPO).as_posix(),
                                         'source_sha256': sha(source), 'generated_sha256': sha(output)}
    # Two frozen helpers need target admission changes, but no wire/crypto changes.
    for name in ('permit_validator.py', 'attempt_plan.py'):
        source = ROOT.parent/'raw_radio_v4_assoc_permit/tools'/name
        output = ROOT/'tools'/name
        text = specialize(source.read_text(), raw)
        text = text.replace(r'\x9b\xfa', r'\x7a\x0b')
        output.write_text(text, encoding='utf-8', newline='\n')
        provenance['tools/'+name] = {'source': source.relative_to(REPO).as_posix(),
                                   'source_sha256': sha(source), 'generated_sha256': sha(output)}
    core = ROOT/'host/core.py'
    text = core.read_text().replace("R.parent/'raw_radio_v4_assoc_permit/tools/permit_validator.py'", "R/'tools/permit_validator.py'")
    text = text.replace("R.parent/'raw_radio_v4_assoc_permit/tools/attempt_plan.py'", "R/'tools/attempt_plan.py'")
    core.write_text(text, encoding='utf-8', newline='\n')
    provenance['host/core.py']['generated_sha256'] = sha(core)
    source = ROOT.parent/'hardware_commissioning_v7/runner.py'
    text = specialize(source.read_text(), raw).split('\ndef verify_inputs():')[0]
    text = text.replace("V7=HERE.parent/'raw_radio_v7_assoc_poll_cca'", 'V7=HERE')
    text = text.replace("seed.get('generation')!=2", "seed.get('generation')!=0")
    text = text.replace("seed.get('attempt')!=OLD_ATTEMPT", "seed.get('attempt') is not None")
    text = text.replace("seed.get('state')!='ASSOCIATED_UNKEYED'", "seed.get('state')!='ALLOCATED_UNUSED'")
    output=ROOT/'runner.py';output.write_text(text,encoding='utf-8',newline='\n')
    provenance['runner.py']={'source':source.relative_to(REPO).as_posix(),'source_sha256':sha(source),'generated_sha256':sha(output)}
    source=ROOT.parent/'hardware_commissioning_v7/tests/test_runner.py'
    output=ROOT/'tests/test_runner.py'
    text=specialize(source.read_text(),raw)
    output.write_text(text,encoding='utf-8',newline='\n')
    provenance['tests/test_runner.py']={'source':source.relative_to(REPO).as_posix(),'source_sha256':sha(source),'generated_sha256':sha(output)}
    source=ROOT.parent/'hardware_commissioning_v7/recovery.py'
    output=ROOT/'recovery.py';output.write_bytes(source.read_bytes())
    provenance['recovery.py']={'source':source.relative_to(REPO).as_posix(),'source_sha256':sha(source),'generated_sha256':sha(output)}
    (ROOT/'evidence/provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')


def main():
    (ROOT/'evidence').mkdir(parents=True, exist_ok=True)
    (ROOT/'build').mkdir(exist_ok=True)
    before_path = ROOT/'.local/protected_before.json'
    if not before_path.exists():
        before_path.parent.mkdir(parents=True, exist_ok=True)
        identity_store.durable(before_path, protected_inventory())
    forbidden = forbidden_inventory()
    record = identity_store.allocate(ROOT/'.local/identity', 1, forbidden)
    # Stable public binding has no epoch, short, Network Key or counter seed.
    profile = {'ctx': 1, 'raw_ieee': record['raw_ieee'], 'pan': 0x0b7a, 'channel': 21,
               'coordinator_short': 0, 'tc_ieee': TC, 'physical_aircontrol_ieee': '00124b0036a18944',
               'physical_short_observed_only': 0xf59f, 'state': 'ALLOCATED_UNUSED',
               'key_epoch': None, 'assigned_short': None, 'next_fc': None,
               'forbidden_count': len(forbidden),
               'forbidden_inventory_sha256': hashlib.sha256('\n'.join(sorted(forbidden)).encode()).hexdigest()}
    path = ROOT/'profile.json'
    if path.exists() and json.loads(path.read_text())['raw_ieee'] != record['raw_ieee']:
        raise RuntimeError('persistent_identity_changed')
    path.write_text(json.dumps(profile, indent=2)+'\n')
    materialize(record)
    print(json.dumps({'identity': record['raw_ieee'], 'hardware_performed': False, 'COM_opened': 0}))


if __name__ == '__main__':
    main()
