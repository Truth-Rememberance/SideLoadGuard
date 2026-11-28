import json
from pathlib import Path

from sg_analysis.analyze import compute_features


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "shared" / "fixtures" / "findings"


def test_compute_features_reproduces_each_fixture():
    for fixture_path in sorted(FIXTURE_DIR.glob("*.json")):
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        assert compute_features(fixture) == fixture["features"], fixture_path.name
