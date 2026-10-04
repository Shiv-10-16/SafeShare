"""Automated test suite for SafeShare."""

import json
import threading
import time
import urllib.request
import uvicorn

from safeshare_engine import GEMMA_4_MODELS, scan_patterns, merge_and_anonymize, restore_text
from scenarios import SCENARIOS
from app import app


def test_unit_logic():
    print("[1] Verifying Gemma 4 Models...")
    assert "gemma-4-31b-it" in GEMMA_4_MODELS
    assert "gemma-4-26b-a4b-it" in GEMMA_4_MODELS
    print("    -> Models registered:", list(GEMMA_4_MODELS.keys()))

    print("\n[2] Testing Regex Pattern Detector...")
    sample_text = (
        "Customer Aadhaar is 4892 7741 9023 and PAN is BDFPS8921K. "
        "Email: test@company.com, Phone: +91 9826014492. "
        "AWS key: AKIAIOSFODNN7EXAMPLE, Server IP: 10.0.1.50"
    )
    findings = scan_patterns(sample_text)
    types_found = [f["entity_type"] for f in findings]
    print(f"    -> Detected {len(findings)} patterns: {types_found}")
    assert any("Aadhaar" in t for t in types_found)
    assert any("PAN" in t for t in types_found)
    assert any("Email" in t for t in types_found)
    assert any("AWS" in t for t in types_found)

    print("\n[3] Testing Non-Standard Formats & Indian Legal Documents...")
    t1 = "aadhar 452009 25009 42009"
    f1 = scan_patterns(t1)
    res1 = merge_and_anonymize(t1, f1, [])
    assert "452009 25009 42009" not in res1["sanitized_text"]
    assert "[AADHAAR_1]" in res1["sanitized_text"]
    print(f"    -> Irregular Aadhaar: '{t1}' -> '{res1['sanitized_text']}'")

    t2 = "rqavi transferred 50k from his hdfc account"
    f2 = scan_patterns(t2)
    res2 = merge_and_anonymize(t2, f2, [])
    assert "rqavi" not in res2["sanitized_text"]
    assert "50k" not in res2["sanitized_text"]
    assert "[CUSTOMER_1]" in res2["sanitized_text"]
    assert "[AMOUNT_1]" in res2["sanitized_text"]
    assert "[ACCOUNT_1]" in res2["sanitized_text"]
    print(f"    -> Conversational Transfer: '{t2}' -> '{res2['sanitized_text']}'")

    t3 = "Pan: ABCDE1234F, Passport: Z1234567, DL: DL-0420110012345, RC: MP09AB1234, GST: 27AAAAA0000A1Z5, ABHA: 12-3456-7890-1234"
    f3 = scan_patterns(t3)
    res3 = merge_and_anonymize(t3, f3, [])
    assert "[PAN_CARD_1]" in res3["sanitized_text"]
    assert "[PASSPORT_1]" in res3["sanitized_text"]
    assert "[DRIVING_LICENSE_1]" in res3["sanitized_text"]
    assert "[VEHICLE_RC_1]" in res3["sanitized_text"]
    assert "[GSTIN_1]" in res3["sanitized_text"]
    assert "[HEALTH_ID_1]" in res3["sanitized_text"]
    print(f"    -> Indian Legal Documents: '{res3['sanitized_text']}'")

    print("\n[4] Testing Reversible Synthetic Anonymization & Vault...")
    merged = merge_and_anonymize(sample_text, findings, [], mask_mode="synthetic")
    sanitized = merged["sanitized_text"]
    vault = merged["vault"]
    assert "4892 7741 9023" not in sanitized
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    print(f"    -> Sanitized Output: {sanitized}")
    print(f"    -> Vault Mapping Count: {len(vault)} entities")

    print("\n[5] Testing Client-Side Vault Restoration...")
    restored = restore_text(sanitized, vault)
    assert restored == sample_text
    print("    -> Re-identification 100% matched original text!")

    print("\n[6] Verifying Benchmark Scenarios...")
    assert len(SCENARIOS) >= 4
    for sid, s in SCENARIOS.items():
        assert len(s["text"]) > 100
        assert s["cached_audit"]["risk_score"] > 80
        print(f"    -> Scenario '{sid}': {len(s['cached_audit']['findings'])} threats verified")

    print("\n[OK] All core SafeShare unit tests passed!")


from desktop_app import find_free_port


class ServerThread(threading.Thread):
    def __init__(self, port: int):
        super().__init__(daemon=True)
        self.port = port
        self.config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self.server = uvicorn.Server(self.config)

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True


def test_live_server():
    print("\n[7] Testing Live HTTP Server Endpoints...")
    test_port = find_free_port(8005)
    server = ServerThread(test_port)
    server.start()
    time.sleep(1.5)
    base = f"http://127.0.0.1:{test_port}"

    try:
        # /api/health
        with urllib.request.urlopen(f"{base}/api/health", timeout=5) as r:
            assert r.status == 200
            data = json.loads(r.read().decode())
            assert data["status"] == "healthy"
            print("    -> /api/health passed")

        # /api/scenarios
        with urllib.request.urlopen(f"{base}/api/scenarios", timeout=5) as r:
            assert r.status == 200
            data = json.loads(r.read().decode())
            assert len(data["scenarios"]) >= 4
            print(f"    -> /api/scenarios passed ({len(data['scenarios'])} loaded)")

        # /api/audit (Benchmark mode)
        req = urllib.request.Request(
            f"{base}/api/audit",
            data=json.dumps({
                "text": SCENARIOS["idfc_banking_dispute"]["text"],
                "scenario_id": "idfc_banking_dispute",
                "use_cached_benchmark": True,
                "mask_mode": "synthetic"
            }).encode(),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            assert r.status == 200
            data = json.loads(r.read().decode())
            assert data["stats"]["risk_score"] > 80
            assert len(data["findings"]) >= 6
            print(f"    -> /api/audit passed (Risk Score: {data['stats']['risk_score']}/100)")

        # /api/guardian/log
        req_log = urllib.request.Request(
            f"{base}/api/guardian/log",
            data=json.dumps({
                "source": "desktop",
                "threats_count": 2,
                "categories": ["GOVERNMENT_ID", "SECRET"],
                "original_text": "Sample Aadhaar 452009 25009 42009",
                "sanitized_text": "Sample Aadhaar [AADHAAR_1]",
                "vault": {"[AADHAAR_1]": "452009 25009 42009"}
            }).encode(),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_log, timeout=5) as r:
            assert r.status == 200
            data = json.loads(r.read().decode())
            assert data["status"] == "ok"
            print("    -> /api/guardian/log passed")

        # /api/guardian/stats
        with urllib.request.urlopen(f"{base}/api/guardian/stats", timeout=5) as r:
            assert r.status == 200
            data = json.loads(r.read().decode())
            assert "total_threats_blocked" in data
            assert len(data["recent_logs"]) >= 1
            print("    -> /api/guardian/stats passed")

        # /api/guardian/toggle
        req_toggle = urllib.request.Request(
            f"{base}/api/guardian/toggle",
            data=json.dumps({"paused": False}).encode(),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_toggle, timeout=5) as r:
            assert r.status == 200
            data = json.loads(r.read().decode())
            assert data["is_paused"] is False
            print("    -> /api/guardian/toggle passed")

        # Static Web UI
        with urllib.request.urlopen(f"{base}/", timeout=5) as r:
            assert r.status == 200
            html = r.read().decode()
            assert "SafeShare" in html
            print("    -> Static web UI served successfully")

        print("\n[SUCCESS] ALL SAFESHARE INTEGRATION TESTS PASSED!")
    finally:
        server.stop()


if __name__ == "__main__":
    test_unit_logic()
    test_live_server()

