"""Offline one-time import from Wireshark key table into ignored secrets file.

Candidate selection here is an explicit provisioning audit, never receive routing.
No key contents are printed, including on failure.
"""
import csv
import json
import os
from pathlib import Path
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from airnanny.security import KeyStore, decrypt, AuthenticationError
from airnanny.nwk import NWK


def main():
    subprocess.run(["git", "check-ignore", "--quiet", "host/airnanny2mqtt/secrets.local.json"],
                   cwd=ROOT.parents[1], check=True)
    source = Path(os.environ["APPDATA"]) / "Wireshark" / "zigbee_pc_keys"
    candidates = []
    for row in csv.reader(source.read_text(encoding="utf-8").splitlines()):
        if not row or row[0].startswith("#"):
            continue
        value = row[0].replace(":", "").replace(" ", "")
        try:
            key = bytes.fromhex(value)
        except ValueError:
            continue
        if len(key) == 16:
            candidates.extend([key, key[::-1]])
    evidence = ROOT.parents[1] / "firmware/airnanny_dual_pan/evidence/capture_layers.json"
    records = json.loads(evidence.read_text(encoding="utf-8"))
    result = {}
    for context, pan in (("CTX0", "0xfa9b"), ("CTX1", "0x0b7a")):
        vectors = [r for r in records if r["fields"]["wpan.dst_pan"] == pan][:3]
        matches = set()
        for key in candidates:
            store = KeyStore()
            store.put(0, key)
            try:
                if all(decrypt(NWK.parse(bytes.fromhex(r["nwk_raw"])), store)[1].hex()
                       == r["aps_decrypted_raw"] for r in vectors):
                    matches.add(key)
            except AuthenticationError:
                pass
        if len(matches) != 1:
            raise RuntimeError("unique authenticated key not found for " + context)
        result[f"AIRNANNY_{context}_NWK_KEY"] = matches.pop().hex()
    (ROOT / "secrets.local.json").write_text(json.dumps(result), encoding="utf-8")
    print("Imported separately authenticated keys for ctx0 and ctx1 into ignored local file.")


if __name__ == "__main__":
    main()
