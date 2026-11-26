import pathlib


def test_rule_positive_and_negative_coverage():
    repository_root = pathlib.Path(__file__).resolve().parents[1]
    rules_dir = repository_root / "analysis" / "rules"
    tests_dir = repository_root / "tests" / "rules"

    if not rules_dir.exists():
        print("Rule test coverage check dormant until rules exist.")
        return

    rule_files = sorted(
        path for path in rules_dir.rglob("*")
        if path.is_file()
    )
    if not rule_files:
        print("Rule test coverage check dormant until rules exist.")
        return

    test_files = []
    if tests_dir.exists():
        test_files = sorted(
            path for path in tests_dir.rglob("*")
            if path.is_file()
        )
    test_text = "\n".join(path.read_text(encoding="utf-8") for path in test_files)

    missing = []
    for rule_file in rule_files:
        rule_name = rule_file.stem
        lower_text = test_text.lower()
        if rule_name.lower() not in lower_text:
            missing.append(str(rule_file.relative_to(repository_root)))
            continue
        if "positive" not in lower_text or "negative" not in lower_text:
            missing.append(str(rule_file.relative_to(repository_root)))

    assert not missing, (
        "Missing positive and/or negative test coverage for rules: "
        + ", ".join(missing)
    )
