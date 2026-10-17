"""Re-run authenticated vector audit and write non-secret milestone evidence."""
from collections import Counter
from dataclasses import replace
import hashlib
import json
import platform
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
import cryptography

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from airnanny.mac import MAC
from airnanny.nwk import NWK
from airnanny.security import KeyStore, encrypt
from airnanny.context import ZigbeeContext
from airnanny.pipeline import receive


def main():
    vectors = json.loads((ROOT / "fixtures/captures.json").read_text())
    provenance = json.loads((ROOT / "fixtures/provenance.json").read_text())
    stores = {}
    for name in ("ctx0", "ctx1"):
        stores[name] = KeyStore()
        local = ROOT / "secrets.local.json"
        stores[name].load(name, local_file=local if local.exists() else None)
    counts = Counter()
    counters, sequences = {}, {}
    reconstructed = 0
    for v in vectors:
        mac = MAC.parse(bytes.fromhex(v["mac_raw"]))
        name = "ctx0" if mac.destination_pan == 0xfa9b else "ctx1"
        ctx = ZigbeeContext(name, mac.destination_pan, 0, 21, 0, mac.destination, 0)
        ctx.keys = stores[name]
        result = receive(mac.serialize(), [ctx])
        assert result.application.serialize().hex() == v["payload"]
        assert result.aps.serialize().hex() == v["aps_decrypted_raw"]
        encrypted = encrypt(result.nwk, result.security, result.aps.serialize(), ctx.keys)
        assert encrypted == result.nwk.payload
        for occurrence in v["occurrences"]:
            hop = MAC.parse(bytes.fromhex(occurrence["mac_raw"]))
            assert replace(hop, payload=replace(result.nwk, payload=encrypted).serialize()).serialize() == hop.serialize()
            reconstructed += 1
        counts[f"{name}_TYPE{v['type']:02d}"] += 1
        if v["type"] == 7 and result.aps.group == 10 and mac.destination == 0:
            counts[f"{name}_controller_to_A7_group_TYPE07"] += 1
        counters.setdefault(name, set()).add(result.security.counter)
        sequences.setdefault(name, set()).add(result.nwk.sequence)
    suite = ET.parse(ROOT / "evidence/pytest.xml").getroot().find("testsuite")
    totals = {k: int(suite.attrib[k]) for k in ("tests", "failures", "errors", "skipped")}
    assert totals["tests"] > 0 and not any(totals[k] for k in ("failures", "errors", "skipped"))
    assert not provenance["discrepancies"]
    sources = {}
    for folder in ("src", "tests", "tools", "fixtures"):
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                sources[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    report = {
        "verdict": "A. OFFLINE CODEC PASS", "date": "2026-10-05", "timezone": "Europe/Moscow",
        "python": platform.python_version(), "cryptography": cryptography.__version__,
        "pytest": "9.1.1", "pytest_totals": totals,
        "capture_files": len(provenance["captures"]), "capture_rows": provenance["source_rows"],
        "unique_vectors": len(vectors), "decrypt_verified": len(vectors),
        "encrypt_reproduction_verified": len(vectors), "mac_occurrences_reproduced": reconstructed,
        "coverage": dict(counts), "distinct_security_counters": {k: len(v) for k, v in counters.items()},
        "distinct_nwk_sequences": {k: len(v) for k, v in sequences.items()},
        "discrepancies": provenance["discrepancies"], "pcap_frames_matches": provenance["previous_matches"],
        "keys": "Separate stores loaded from ignored secrets.local.json; no key material in evidence",
        "offline_proven": ["captured parsing", "MIC-verified decryption", "byte-identical ciphertext/MIC and MAC reproduction",
                           "context isolation", "strict replay/duplicate rejection", "reservation/crash algorithm with surviving memory store"],
        "not_proven": ["custom frame accepted by A7", "production counters or durable storage", "membership/liveness",
                       "dongle transport", "simultaneous dual-PAN radio", "management frames", "key updates", "provisioning"],
        "unsupported": ["MAC extended addressing/security/ACK/IE/version1+", "NWK optional extended addresses/source routes/multicast controls",
                        "APS security/fragmentation/ACK", "ZCL command semantics", "SAFE controls", "daemon/MQTT/HA"],
        "source_sha256": sources,
    }
    (ROOT / "evidence/python_zigbee_codec_v1.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("source_sha256", "unsupported", "not_proven", "offline_proven")}))


if __name__ == "__main__":
    main()
