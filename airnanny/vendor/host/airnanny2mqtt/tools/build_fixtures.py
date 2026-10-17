"""Read-only capture/evidence audit; all writes stay below this project."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
WORKSPACE = REPO.parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    source = REPO / "firmware/airnanny_dual_pan/evidence/capture_layers.json"
    extracted = WORKSPACE / "builds/pcap_frames.json"
    records = json.loads(source.read_text(encoding="utf-8"))
    previous = {(r["file"], r["frame"]): r for r in json.loads(extracted.read_text(encoding="utf-8"))}
    provenance = {"capture_layers_sha256": digest(source), "pcap_frames_sha256": digest(extracted),
                  "captures": {}, "discrepancies": [], "previous_matches": 0}
    for path in sorted((WORKSPACE / "pcaps").glob("*.pcapng")):
        packets = json.loads(subprocess.check_output([
            r"C:\Program Files\Wireshark\tshark.exe", "-r", str(path), "-T", "json", "-x"
        ], stderr=subprocess.PIPE))
        provenance["captures"][path.name] = {"sha256": digest(path), "frames": len(packets)}
        for record in [r for r in records if r["file"] == path.name]:
            layers = packets[record["frame"] - 1]["_source"]["layers"]
            for expected, actual in (("mac_raw", "wpan_raw"), ("nwk_raw", "zbee_nwk_raw"),
                                     ("aps_decrypted_raw", "zbee_aps_raw"), ("zcl_raw", "zbee_zcl_raw")):
                if record[expected] != layers[actual][0]:
                    provenance["discrepancies"].append([path.name, record["frame"], expected])
            old = previous.get((path.name, record["frame"]))
            if old:
                provenance["previous_matches"] += 1
                if old["payload"] != record["payload"]:
                    provenance["discrepancies"].append([path.name, record["frame"], "pcap_frames payload"])
    # Group by PAN + entire secured NWK bytes, excluding hop-local MAC retry DSN.
    unique = {}
    for r in records:
        identity = (r["fields"]["wpan.dst_pan"], r["nwk_raw"])
        if identity not in unique:
            unique[identity] = {k: r[k] for k in ("file", "frame", "type", "fields", "mac_raw", "nwk_raw", "aps_decrypted_raw", "zcl_raw", "payload")}
            unique[identity]["occurrences"] = []
        unique[identity]["occurrences"].append({"file": r["file"], "frame": r["frame"], "mac_raw": r["mac_raw"]})
    provenance.update(source_rows=len(records), unique_vectors=len(unique),
                      deduplication="PAN + complete secured NWK bytes; hop-local MAC excluded")
    out = ROOT / "fixtures"
    out.mkdir(exist_ok=True)
    (out / "captures.json").write_text(json.dumps(list(unique.values()), indent=2), encoding="utf-8")
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in provenance.items() if k != "captures"}))
    if provenance["discrepancies"]:
        raise SystemExit("Capture/evidence discrepancies require review")


if __name__ == "__main__":
    main()
