"""Bind the reviewed V22 FAN adapter to ctx1, with no serial or RF entrypoint.

The classes are extracted from frozen sources; only context literals differ.
Live authority must come from the commissioned ctx1 ledger, never this module.
"""
import ast
from dataclasses import dataclass
import hashlib
import re
import sys
from pathlib import Path
from bindings import PROFILE

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
sys.path.insert(0, str(REPO/'host/airnanny2mqtt/src'))


@dataclass(frozen=True)
class ApplicationBinding:
    ctx: int
    pan: int
    raw_ieee: str
    tc_ieee: str
    epoch: str
    attempt: str
    peer_short: int

    def __post_init__(self):
        if (self.ctx,self.pan,self.raw_ieee,self.tc_ieee) != (1,PROFILE['pan'],PROFILE['raw_ieee'],PROFILE['tc_ieee']):
            raise ValueError('ctx1_application_binding')
        if not all(re.fullmatch('[0-9a-f]{32}',x) for x in (self.epoch,self.attempt)):
            raise ValueError('application_epoch_or_attempt')
        if self.epoch=='1ea30211ee014345a8288337a173a833' or self.attempt=='5b09cb6bc02746298fbffcfb780844a5':
            raise ValueError('ctx0_application_authority')
        if not 0<self.peer_short<0xfff8:
            raise ValueError('current_authenticated_peer_short_required')


def extracted(path, names):
    text=path.read_text();tree=ast.parse(text);lines=text.splitlines(keepends=True)
    nodes=[n for n in tree.body if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name in names]
    if {n.name for n in nodes} != set(names):raise ValueError('reviewed_source_shape_changed')
    return '\n'.join(''.join(lines[n.lineno-1:n.end_lineno]) for n in nodes)


def adapter(binding):
    from key_announce import oracle
    from airnanny.application import Type06,Type07
    from airnanny.baseline import Baseline
    from airnanny.commands import CommandRequest,build
    from airnanny.confirmation import Confirmation
    from airnanny.context import ZigbeeContext
    from airnanny.config import DeviceConfig
    from airnanny.counters import CounterAllocator
    from airnanny.outgoing import secured_frame
    from airnanny.aps import APS
    from airnanny.zcl import ZCL
    namespace=dict(oracle=oracle,Type06=Type06,Type07=Type07,Baseline=Baseline,
        CommandRequest=CommandRequest,build=build,Confirmation=Confirmation,ZigbeeContext=ZigbeeContext,
        DeviceConfig=DeviceConfig,CounterAllocator=CounterAllocator,secured_frame=secured_frame,APS=APS,ZCL=ZCL,
        RAW=binding.raw_ieee,TC=binding.tc_ieee,EPOCH=binding.epoch,ATTEMPT=binding.attempt,
        PEER=PROFILE['physical_aircontrol_ieee'],Fault=ValueError,hashlib=hashlib,
        le=lambda x,n=2:x.to_bytes(n,'little'))
    decode=extracted(ROOT.parent/'raw_radio_v8_post_announce_management/host/management.py',['decode_nwk'])
    source=extracted(ROOT.parent/'raw_radio_v22_clock_dispatch/host/application_control.py',
                     ['DurableApplicationCounters','FirstFanControl'])
    source=source.replace('0xfa9b',hex(binding.pan)).replace('0xc9b7',hex(binding.peer_short))
    source=source.replace('raw-first-control','ctx1-first-control')
    decode=decode.replace('0xfa9b',hex(binding.pan))
    exec(compile(decode+'\n'+source,'<reviewed_ctx1_application_adapter>','exec'),namespace)
    return namespace['FirstFanControl']
