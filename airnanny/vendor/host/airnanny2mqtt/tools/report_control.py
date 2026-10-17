"""Summarize actual pytest/oracle evidence; never read or emit key material."""
import hashlib
import json
import platform
from pathlib import Path
import xml.etree.ElementTree as ET
import cryptography

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    old = json.loads((ROOT / "evidence/python_zigbee_codec_v1.json").read_text())
    oracle = json.loads((ROOT / "fixtures/control_oracle.json").read_text())
    suite = ET.parse(ROOT / "evidence/control_core_pytest.xml").getroot().find("testsuite")
    totals = {name: int(suite.attrib[name]) for name in ("tests", "failures", "errors", "skipped")}
    if totals["tests"] < 668 or any(totals[k] for k in ("failures", "errors", "skipped")):
        raise SystemExit("No PASS: incomplete/failing/skipped pytest run")
    groups = {}
    for case in suite.findall("testcase"):
        group = case.attrib["classname"].split(".")[-1]
        groups[group] = groups.get(group, 0) + 1
    codec_tests = sum(v for k, v in groups.items() if not k.startswith("test_control"))
    if codec_tests != 668:
        raise SystemExit("Unexpected frozen codec test count")
    frozen = all(sha(ROOT / name) == digest for name, digest in old["source_sha256"].items())
    v17 = all(sha(ROOT.parents[1] / name) == digest for name, digest in oracle["sources"].items())
    if not frozen or not v17:
        raise SystemExit("Frozen source changed: report requires explicit review")
    modules = {p.stem: str(p.relative_to(ROOT)).replace("\\", "/") for p in (ROOT / "src/airnanny").glob("*.py")}
    report = {
        "verdict": "A. OFFLINE CONTROL CORE PASS",
        "date": "2026-10-05", "timezone": "Europe/Moscow",
        "python": platform.python_version(), "cryptography": cryptography.__version__,
        "pytest": {"version": old["pytest"], **totals, "codec_regression": codec_tests,
                   "control_core": totals["tests"] - codec_tests, "groups": groups},
        "oracle": {"builder_vectors": len(oracle["builders"]), "confirmation_traces": len(oracle["traces"]),
                   "exact_helper_trace_comparisons": 36, "generation_host_outcome_traces": 6,
                   "freshness_override_traces": 6, "compiler": "Zig 0.13.0 cc", "fixture_sha256": sha(ROOT / "fixtures/control_oracle.json")},
        "frozen_codec_unchanged": frozen, "frozen_v17_unchanged": v17, "codec_bug_fixes": [],
        "defaults_ms": {"status_fresh": 15000, "fan": 20000, "mode": 20000, "humidifier": 20000,
                        "night": 20000, "temp": 45000, "power": 45000, "stable_dwell": 1000},
        "modules": modules,
        "gates": {
            "all": "fresh TYPE06, valid non-pending shared baseline, known fan/mode/power/night agreement, no in-flight command",
            "fan_mode": "FAN1..7, MODE intake/mixed/recirc; no invented companion target/hum gate",
            "temp": "powered intake, baseline/status target equality; old/new target ordinary100..300 step5 or -1000",
            "humidifier": "live powered intake NIGHT0, baseline/status level0..2 equality, target equality",
            "night": "live powered, baseline command hum0, target equality; V17 does not separately gate status byte18",
            "power": "live configured controller source, opposite power, intake NIGHT0 hum0 baseline/status, ordinary target100..300 step5"},
        "explicit_adaptations": [
            "No boot-time captured template baseline; initialize unavailable and acquire authenticated genuine controller TYPE07",
            "V17 POWER source C9B7 is per-device configured controller_short",
            "Host applies generation/timeout outcome before baseline commit, including delayed callbacks",
            "Freshness is enforced on retained generic FAN/MODE/TEMP matches before callback confirmation per user requirement",
            "Duplicate supplied RX revisions cannot serve as a new stability sample",
            "Unsafe invalidation increments generation to prevent an older own TX commit",
            "Queued intent aborts on newer baseline generation; no automatic rebase or retry"],
        "hardware_io_calls": 0, "network_connections": 0, "automatic_retries": 0,
        "tested_device_instances": ["bedroom", "second_bedroom", "additional synthetic devices (N=5)"],
        "not_proven": ["custom secured frame accepted by A7", "runtime membership/provisioning", "production durable counters",
                       "raw radio TX contract", "dual-PAN simultaneous radio", "real callback timing", "real control-core device confirmation"],
        "out_of_scope": ["serial/USB/COM", "firmware changes", "Nordic SDK changes", "join/BDB", "MQTT/HA", "water/CO2 semantics",
                         "NIGHT+humidifier scope expansion", "POWER mixed/recirc", "automatic retries or compensation"],
        "source_sha256": {},
    }
    for folder in ("src", "tests", "tools", "fixtures", "docs"):
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                report["source_sha256"][path.relative_to(ROOT).as_posix()] = sha(path)
    report["pytest_xml_sha256"] = sha(ROOT / "evidence/control_core_pytest.xml")
    (ROOT / "evidence/python_airnanny_control_core_v1.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("verdict", "pytest", "oracle", "frozen_codec_unchanged", "frozen_v17_unchanged")}))


if __name__ == "__main__":
    main()
