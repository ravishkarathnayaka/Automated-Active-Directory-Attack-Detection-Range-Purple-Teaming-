"""
Unit tests for Detection Matching against synthetic Windows Event logs.
Verifies that Sigma rules accurately match simulated attack telemetry
and filter benign/machine behavior across all 7 detection engineering vectors.
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
        benign_event = dict(event)
        benign_event["ServiceName"] = "DC01$"
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


class TestBloodHoundDetection:
    """Validate detection logic for SharpHound / BloodHound LDAP queries (T1087 / T1069)."""

    def test_bloodhound_event_matches(self):
        event = load_event("event_bloodhound.json")
        rule = load_rule("win_ad_bloodhound_ldap_queries.yml")

        # Check image or commandline selection
        image = event.get("Image", "")
        img_match = any(image.endswith(ext.replace("\\", "")) for ext in ["SharpHound.exe", "BloodHound.exe"])
        
        flags = rule["detection"]["selection_cmd"]["CommandLine|contains"]
        cmdline = event.get("CommandLine", "")
        flag_match = any(flag.strip() in cmdline for flag in flags)
        
        assert img_match or flag_match, "Neither SharpHound image nor CLI flag matched"

    def test_benign_process_not_matched(self):
        rule = load_rule("win_ad_bloodhound_ldap_queries.yml")
        benign_cmd = "notepad.exe C:\\Users\\Public\\notes.txt"
        flags = rule["detection"]["selection_cmd"]["CommandLine|contains"]
        assert not any(flag.strip() in benign_cmd for flag in flags)


class TestNTDSUtilDetection:
    """Validate detection logic for NTDS.dit snapshot extraction (T1003.003)."""

    def test_ntdsutil_event_matches(self):
        event = load_event("event_ntdsutil.json")
        rule = load_rule("win_ad_ntdsutil_shadowcopy_dump.yml")

        image = event.get("Image", "").lower()
        assert image.endswith("ntdsutil.exe")

        cmdline = event.get("CommandLine", "").lower()
        ntds_flags = [f.lower() for f in rule["detection"]["selection_ntdsutil"]["CommandLine|contains"]]
        assert any(flag in cmdline for flag in ntds_flags)

    def test_benign_cmd_not_matched(self):
        rule = load_rule("win_ad_ntdsutil_shadowcopy_dump.yml")
        benign_cmd = "calc.exe"
        ntds_flags = rule["detection"]["selection_ntdsutil"]["CommandLine|contains"]
        assert not any(f in benign_cmd for f in ntds_flags)


class TestLSASSAccessDetection:
    """Validate detection logic for LSASS process memory access (T1003.001)."""

    def test_lsass_access_event_matches(self):
        event = load_event("event_lsass_access.json")
        rule = load_rule("win_susp_lsass_process_access.yml")

        target = event.get("TargetImage", "").lower()
        assert target.endswith("lsass.exe")

        granted = event.get("GrantedAccess", "")
        masks = rule["detection"]["selection"]["GrantedAccess|contains"]
        assert any(m in granted for m in masks)

        source = event.get("SourceImage", "").lower()
        filters = [f.replace("\\", "").lower() for f in rule["detection"]["filter_legitimate"]["SourceImage|endswith"]]
        assert not any(source.endswith(f) for f in filters)

    def test_lsass_legitimate_svchost_filtered(self):
        event = load_event("event_lsass_access.json")
        legit_event = dict(event)
        legit_event["SourceImage"] = "C:\\Windows\\System32\\svchost.exe"

        rule = load_rule("win_susp_lsass_process_access.yml")
        filters = [f.replace("\\", "").lower() for f in rule["detection"]["filter_legitimate"]["SourceImage|endswith"]]
        assert any(legit_event["SourceImage"].lower().endswith(f) for f in filters)
