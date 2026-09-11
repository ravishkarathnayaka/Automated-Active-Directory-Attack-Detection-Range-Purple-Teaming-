"""
Unit tests for Sigma Rule Syntax and Specification Compliance.
Validates that all Sigma rules in detections/sigma/ adhere to the Sigma v2 specification
and successfully parse using pySigma.
"""

from pathlib import Path
import pytest
import yaml
from sigma.collection import SigmaCollection

SIGMA_DIR = Path(__file__).resolve().parent.parent / "detections" / "sigma"
SIGMA_FILES = sorted(list(SIGMA_DIR.glob("*.yml")) + list(SIGMA_DIR.glob("*.yaml")))


@pytest.mark.parametrize("rule_path", SIGMA_FILES, ids=lambda p: p.name)
def test_sigma_rule_yaml_syntax(rule_path: Path):
    """Ensure rule file is valid YAML and can be loaded."""
    with open(rule_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), f"{rule_path.name} did not parse into a dictionary"


@pytest.mark.parametrize("rule_path", SIGMA_FILES, ids=lambda p: p.name)
def test_sigma_rule_pysigma_parsing(rule_path: Path):
    """Ensure rule complies with the Sigma specification using pySigma parser."""
    content = rule_path.read_text(encoding="utf-8")
    collection = SigmaCollection.from_yaml(content)
    assert len(collection.rules) >= 1, f"No rules parsed from {rule_path.name}"
    rule = collection.rules[0]
    assert rule.title, f"Missing title in {rule_path.name}"


@pytest.mark.parametrize("rule_path", SIGMA_FILES, ids=lambda p: p.name)
def test_sigma_rule_mandatory_fields(rule_path: Path):
    """Check presence of mandatory metadata fields in each rule."""
    with open(rule_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    required_fields = [
        "title",
        "id",
        "status",
        "description",
        "author",
        "logsource",
        "detection",
        "level",
        "tags",
    ]
    for field in required_fields:
        assert field in data, f"Missing required field '{field}' in {rule_path.name}"

    assert "condition" in data["detection"], f"Missing 'condition' in detection of {rule_path.name}"
    assert isinstance(data["tags"], list), f"'tags' must be a list in {rule_path.name}"
    assert len(data["tags"]) > 0, f"'tags' must not be empty in {rule_path.name}"
    assert any(tag.startswith("attack.") for tag in data["tags"]), (
        f"At least one MITRE ATT&CK tag required in {rule_path.name}"
    )
