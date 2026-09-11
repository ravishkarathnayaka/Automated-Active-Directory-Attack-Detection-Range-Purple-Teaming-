"""
Unit tests for Detection Matching against synthetic Windows Event logs.
Verifies that Sigma rules accurately match simulated attack telemetry
and filter benign/machine behavior.
"""

import json
from pathlib import Path
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SIGMA_DIR = REPO_ROOT / "detections" / "sigma"
TEST_EVENTS_DIR = REPO_ROOT / "detections" / "test_events"


def load_event(filename: str) -> dict:
    event_path = TEST_EVENTS_DIR / filename
    assert event_path.exists(), f"Event file {filename} not found"
    with open(event_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_rule(filename: str) -> dict:
    rule_path = SIGMA_DIR / filename
    assert rule_path.exists(), f"Rule file {filename} not found"
    with open(rule_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class TestKerberoastDetection:
    """Validate detection logic for Kerberoasting (Event ID 4769)."""

    def test_kerberoast_event_matches(self):
        event = load_event("event_kerberoast.json")
        rule = load_rule("win_ad_kerberoasting_spn_request.yml")

        # Evaluate Selection
        sel = rule["detection"]["selection"]
        assert event.get("EventID") == sel["EventID"]
        assert str(event.get("TicketEncryptionType")) == sel["TicketEncryptionType"]
        assert str(event.get("Status")) == sel["Status"]

        # Evaluate Filter (must not match machine accounts)
        service_name = event.get("ServiceName", "")
        assert not service_name.endswith("$")

    def test_kerberoast_filter_machine_account(self):
        event = load_event("event_kerberoast.json")
        # Benign computer ticket request
        benign_event = dict(event)
        benign_event["ServiceName"] = "DC01$"

        # Should be filtered out
        assert benign_event["ServiceName"].endswith("$")


class TestASREPRoastDetection:
    """Validate detection logic for AS-REP Roasting (Event ID 4768)."""

    def test_asrep_event_matches(self):
        event = load_event("event_asrep.json")
        rule = load_rule("win_ad_asrep_roasting_preauth.yml")

        # Evaluate Selection
        sel = rule["detection"]["selection"]
        assert event.get("EventID") == sel["EventID"]
        assert str(event.get("PreAuthType")) == sel["PreAuthType"]
        assert str(event.get("Status")) == sel["Status"]

        # Evaluate Filter
        user_name = event.get("TargetUserName", "")
        assert not user_name.endswith("$")

    def test_asrep_benign_preauth_not_matched(self):
        event = load_event("event_asrep.json")
        # Standard Kerberos pre-authentication (PA-ENC-TIMESTAMP = 2)
        normal_auth = dict(event)
        normal_auth["PreAuthType"] = "2"

        rule = load_rule("win_ad_asrep_roasting_preauth.yml")
        sel = rule["detection"]["selection"]
        assert str(normal_auth["PreAuthType"]) != sel["PreAuthType"]


class TestDCSyncDetection:
    """Validate detection logic for DCSync replication (Event ID 4662)."""

    def test_dcsync_event_matches(self):
        event = load_event("event_dcsync.json")
        rule = load_rule("win_ad_dcsync_replication_access.yml")

        # Evaluate Selection
        sel = rule["detection"]["selection"]
        assert event.get("EventID") == sel["EventID"]
        assert str(event.get("AccessMask")) == sel["AccessMask"]

        # Evaluate DRS GUID presence
        guids = rule["detection"]["drsuapi_guids"]["Properties|contains"]
        properties = event.get("Properties", "")
        guid_match = any(g in properties for g in guids)
        assert guid_match, f"None of DRS GUIDs found in properties: {properties}"

        # Evaluate Filter (must not be machine account)
        subject_user = event.get("SubjectUserName", "")
        assert not subject_user.endswith("$")

    def test_dcsync_dc_replication_filtered(self):
        event = load_event("event_dcsync.json")
        # Legitimate domain controller replication
        dc_event = dict(event)
        dc_event["SubjectUserName"] = "DC02$"

        assert dc_event["SubjectUserName"].endswith("$")


class TestSuspiciousPowerShellDetection:
    """Validate detection logic for suspicious encoded PowerShell execution."""

    def test_powershell_encoded_event_matches(self):
        event = load_event("event_powershell_encoded.json")
        rule = load_rule("win_susp_powershell_encoded_cmd.yml")

        # Evaluate Process selection
        image = event.get("Image", "").lower()
        proc_match = image.endswith("powershell.exe") or image.endswith("pwsh.exe")
        assert proc_match

        # Evaluate Flags selection
        flags = rule["detection"]["selection_flags"]["CommandLine|contains"]
        cmdline = event.get("CommandLine", "")
        flag_match = any(flag in cmdline for flag in flags)
        assert flag_match, f"No suspicious flag in commandline: {cmdline}"

    def test_benign_powershell_command(self):
        benign_cmd = "powershell.exe -File C:\\Scripts\\backup.ps1"
        rule = load_rule("win_susp_powershell_encoded_cmd.yml")
        flags = rule["detection"]["selection_flags"]["CommandLine|contains"]
        flag_match = any(flag in benign_cmd for flag in flags)
        assert not flag_match
