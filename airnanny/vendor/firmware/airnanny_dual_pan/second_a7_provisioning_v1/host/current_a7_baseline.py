"""Passive current-A7 predicate, separate from frozen exact permit authorization.

Only captured base-header NWK DATA forms0208/0248; authenticated TYPE06 or
exact historical ZDO0036 subset. No serial, persistence, provisioning or TX.
The frozen PermitValidator owns the shared same-source/key-epoch watermark.
"""
from dataclasses import dataclass, asdict
from functools import reduce
from operator import xor
from cryptography.exceptions import InvalidTag
from core import permit_module, Secret

class BaselineRejected(ValueError):
    def __init__(self, reason, diagnostic):
        super().__init__(reason)
        self.diagnostic = dict(diagnostic, accepted=False, reason=reason)

@dataclass(frozen=True)
class BaselineEvidence:
    revision: int
    pan: int
    security_source: str
    keyseq: int
    security_fc: int
    nwk_fcf: str
    semantic_policy: str
    mic_valid: bool = True
    accepted: bool = True

class A7Preconditions:
    def __init__(self, permit_validator, key: Secret):
        p = permit_validator
        if (p.pan != 0x0b7a or p.coordinator != '00124b0036a1875f' or
                p.key_sequence != 0 or p.ctx != 1 or not p.key_epoch or
                p.generation <= 0 or p.key != key.value):
            raise ValueError('unconfigured_candidate_epoch')
        self.permit = p
        self.key = key
        self.context = (p.boot, p.pan, p.coordinator, p.key_sequence,
                        p.key_epoch, p.generation, p.ctx)

    def _context_unchanged(self):
        p = self.permit
        if self.context != (p.boot, p.pan, p.coordinator, p.key_sequence,
                            p.key_epoch, p.generation, p.ctx) or p.key != self.key.value:
            raise ValueError('configured_epoch_or_context_changed_STOP')

    def validate_pairing_permit(self, **args):
        # Do not rewrite/extend the frozen permit predicate or prime its FC first.
        self._context_unchanged()
        return self.permit.validate(**args)

    def validate_current_a7_baseline(self, *, raw, boot, revision,
                                     observed, now, generation):
        p = self.permit
        d = {'revision': revision, 'pan': None, 'security_source': None,
             'keyseq': None, 'security_fc': None, 'nwk_fcf': None,
             'mic_valid': None, 'semantic_policy': None}
        def reject(reason): raise BaselineRejected(reason, d)
        try: self._context_unchanged()
        except ValueError: reject('configured_epoch_or_context_changed_STOP')
        if boot != p.boot or generation != p.generation: reject('boot_or_generation')
        if not p.revision_floor < revision or revision <= p.last_revision: reject('old_RX_revision')
        if not 0 <= now-observed <= 10: reject('stale_or_future_RX')
        if not 9 <= len(raw) <= 125: reject('malformed_MAC_length')
        try: m = permit_module.codec.Mac.parse(raw)
        except ValueError: reject('malformed_MAC')
        d['pan'] = int.from_bytes(m.dst_pan, 'little') if m.dst_pan else None
        if m.fcf not in (0x8841, 0x8861): reject('unsupported_MAC_shape')
        if d['pan'] != p.pan: reject('wrong_PAN')
        if m.src != b'\0\0': reject('MAC_source_not_coordinator')
        n = m.payload
        if len(n) < 26: reject('truncated_NWK_security')
        fcf = int.from_bytes(n[:2], 'little'); d['nwk_fcf'] = f'{fcf:04x}'
        # Exact whitelist excludes commands/inter-PAN, reserved bits, multicast,
        # source routing, IEEE-address extensions and end-device-initiator.
        if fcf not in (0x0208, 0x0248): reject('unsupported_NWK_FCF_semantics')
        if n[4:6] != b'\0\0': reject('NWK_source_not_coordinator')
        dest = int.from_bytes(n[2:4], 'little')
        if dest <= 0xfff7:
            if dest == 0 or m.dst != n[2:4] or m.fcf != 0x8861:
                reject('impossible_unicast_addressing')
        elif dest == 0xfffc:
            if m.dst != b'\xff\xff' or m.fcf != 0x8841 or fcf != 0x0208:
                reject('unsupported_broadcast_addressing')
        else: reject('unsupported_destination')
        if n[6] == 0: reject('zero_radius')
        if n[8] != 0x28: reject('unsupported_security_control')
        try: plain, meta = permit_module.codec.secured_decode(n[:8], n[8:], self.key.value, (0x28,))
        except InvalidTag:
            d['mic_valid'] = False; reject('invalid_MIC')
        except (ValueError, AssertionError): reject('malformed_security_envelope')
        d.update(mic_valid=True, security_source=meta['source_ieee'],
                 keyseq=meta['keyseq'], security_fc=meta['counter'])
        if meta['source_ieee'] != p.coordinator: reject('wrong_security_source')
        if meta['keyseq'] != p.key_sequence: reject('wrong_keyseq_STOP')
        if meta['counter'] >= 0xffffffff: reject('exhausted_security_counter_STOP')
        if meta['counter'] <= p.highest_fc: reject('replayed_or_lower_security_FC')
        if dest <= 0xfff7:
            # Observed APS DATA unicast, EP8/cluster0006/profile0104/EP8,
            # unencrypted APS, ZCL11/cmd01, exact TYPE06 envelope and XOR.
            if (len(plain) != 34 or plain[:7] != bytes.fromhex('00080600040108') or
                    plain[8] != 0x11 or plain[10] != 1): reject('unsupported_APS_ZCL_status')
            status = plain[11:]
            if (status[:6] != bytes.fromhex('706500001106') or
                    reduce(xor, status[5:-1], 0) != status[-1]): reject('invalid_TYPE06_envelope')
            policy = 'captured_A7_TYPE06_unicast'
        else:
            if (len(plain) != 11 or plain[:7] != bytes.fromhex('08003600000000') or
                    plain[9:] != bytes([180, 1])): reject('unsupported_APS_ZDO_broadcast')
            policy = 'exact_ZDO0036_observation_only'
        # Commit only after ALL authentication, semantics/context and freshness
        # checks. Failed observations do not touch either domain watermark.
        p.highest_fc = meta['counter']; p.last_revision = revision
        return BaselineEvidence(revision, p.pan, meta['source_ieee'], meta['keyseq'],
                                meta['counter'], f'{fcf:04x}', policy)

def diagnostic(evidence): return asdict(evidence)
