"""Tests for YAML custom rules and Sigma rule compatibility."""

import tempfile
from datetime import datetime
from pathlib import Path

from tests.conftest import make_failed_logon, make_process_event
from threatlens.models import Severity
from threatlens.rules.sigma_loader import SigmaRule, load_sigma_rules
from threatlens.rules.yaml_rules import YamlRule, load_yaml_rules


class TestYamlRules:
    def test_rule_matches(self):
        rule = YamlRule({
            "name": "Test Rule",
            "description": "Test detection",
            "severity": "high",
            "conditions": [
                {"field": "event_id", "operator": "equals", "value": "4625"},
            ],
            "threshold": 1,
        })
        alerts = rule.analyze([make_failed_logon(datetime(2025, 1, 15, 8, 30, 0))])
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.HIGH

    def test_rule_no_match(self):
        rule = YamlRule({
            "name": "Test Rule",
            "description": "Test detection",
            "severity": "high",
            "conditions": [
                {"field": "event_id", "operator": "equals", "value": "9999"},
            ],
            "threshold": 1,
        })
        alerts = rule.analyze([make_failed_logon(datetime(2025, 1, 15, 8, 30, 0))])
        assert len(alerts) == 0

    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "rules:\n"
                '  - name: "Custom Failed Logon"\n'
                '    description: "Detect failed logons"\n'
                "    severity: medium\n"
                "    conditions:\n"
                "      - field: event_id\n"
                "        operator: equals\n"
                '        value: "4625"\n'
                "    threshold: 1\n"
            )
            f.flush()
            rules = load_yaml_rules(Path(f.name))

        assert len(rules) == 1
        assert rules[0].name == "Custom Failed Logon"

    def test_contains_operator(self):
        rule = YamlRule({
            "name": "Cmd Contains",
            "description": "Test contains operator",
            "severity": "medium",
            "conditions": [
                {"field": "command_line", "operator": "contains", "value": "encodedcommand"},
            ],
            "threshold": 1,
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe -encodedcommand ABC123",
        )]
        alerts = rule.analyze(events)
        assert len(alerts) == 1

    def test_regex_operator(self):
        rule = YamlRule({
            "name": "Regex Rule",
            "description": "Test regex operator",
            "severity": "high",
            "conditions": [
                {"field": "command_line", "operator": "regex", "value": r"reg\s+save.*\\sam"},
            ],
            "threshold": 1,
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "reg.exe",
            "reg save HKLM\\SAM C:\\Temp\\sam.hiv",
        )]
        alerts = rule.analyze(events)
        assert len(alerts) == 1

    def test_startswith_operator(self):
        rule = YamlRule({
            "name": "Startswith Rule",
            "conditions": [{"field": "process_name", "operator": "startswith", "value": "power"}],
            "threshold": 1,
        })
        events = [make_process_event(datetime(2025, 1, 15, 9, 0, 0), "powershell.exe", "test")]
        assert len(rule.analyze(events)) == 1

    def test_endswith_operator(self):
        rule = YamlRule({
            "name": "Endswith Rule",
            "conditions": [{"field": "process_name", "operator": "endswith", "value": ".exe"}],
            "threshold": 1,
        })
        events = [make_process_event(datetime(2025, 1, 15, 9, 0, 0), "powershell.exe", "test")]
        assert len(rule.analyze(events)) == 1

    def test_not_equals_operator(self):
        rule = YamlRule({
            "name": "Not Equals",
            "conditions": [{"field": "event_id", "operator": "not_equals", "value": "9999"}],
            "threshold": 1,
        })
        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, 0))]
        assert len(rule.analyze(events)) == 1

    def test_not_contains_operator(self):
        rule = YamlRule({
            "name": "Not Contains",
            "conditions": [{"field": "command_line", "operator": "not_contains", "value": "malware"}],
            "threshold": 1,
        })
        events = [make_process_event(datetime(2025, 1, 15, 9, 0, 0), "cmd.exe", "dir C:\\")]
        assert len(rule.analyze(events)) == 1

    def test_gt_lt_operators(self):
        rule = YamlRule({
            "name": "GT Rule",
            "conditions": [{"field": "event_id", "operator": "gt", "value": "4000"}],
            "threshold": 1,
        })
        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, 0))]  # event_id=4625
        assert len(rule.analyze(events)) == 1

        rule_lt = YamlRule({
            "name": "LT Rule",
            "conditions": [{"field": "event_id", "operator": "lt", "value": "5000"}],
            "threshold": 1,
        })
        assert len(rule_lt.analyze(events)) == 1

    def test_gte_lte_operators(self):
        rule = YamlRule({
            "name": "GTE Rule",
            "conditions": [{"field": "event_id", "operator": "gte", "value": "4625"}],
            "threshold": 1,
        })
        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, 0))]
        assert len(rule.analyze(events)) == 1

        rule_lte = YamlRule({
            "name": "LTE Rule",
            "conditions": [{"field": "event_id", "operator": "lte", "value": "4625"}],
            "threshold": 1,
        })
        assert len(rule_lte.analyze(events)) == 1

    def test_in_operator(self):
        rule = YamlRule({
            "name": "In Rule",
            "conditions": [{"field": "event_id", "operator": "in", "value": ["4624", "4625", "4626"]}],
            "threshold": 1,
        })
        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, 0))]
        assert len(rule.analyze(events)) == 1

    def test_group_by_with_threshold_and_window(self):
        from datetime import timedelta
        rule = YamlRule({
            "name": "Grouped Rule",
            "description": "Grouped detection",
            "severity": "medium",
            "conditions": [{"field": "event_id", "operator": "equals", "value": "4625"}],
            "group_by": "source_ip",
            "threshold": 3,
            "window_seconds": 300,
        })
        base = datetime(2025, 1, 15, 8, 30, 0)
        events = [
            make_failed_logon(base + timedelta(seconds=i), source_ip="10.0.1.50")
            for i in range(5)
        ]
        alerts = rule.analyze(events)
        assert len(alerts) == 1
        assert "5 matching" in alerts[0].description

    def test_group_by_below_threshold(self):
        rule = YamlRule({
            "name": "Grouped Rule",
            "conditions": [{"field": "event_id", "operator": "equals", "value": "4625"}],
            "group_by": "source_ip",
            "threshold": 10,
            "window_seconds": 300,
        })
        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, 0))]
        assert len(rule.analyze(events)) == 0

    def test_threshold_no_group_by(self):
        rule = YamlRule({
            "name": "Threshold Rule",
            "description": "Needs 3 matches",
            "conditions": [{"field": "event_id", "operator": "equals", "value": "4625"}],
            "threshold": 3,
        })
        from datetime import timedelta
        base = datetime(2025, 1, 15, 8, 30, 0)
        events = [make_failed_logon(base + timedelta(seconds=i)) for i in range(5)]
        alerts = rule.analyze(events)
        assert len(alerts) == 1
        assert "5 matching" in alerts[0].description

    def test_threshold_no_group_by_below_threshold(self):
        rule = YamlRule({
            "name": "Threshold Rule",
            "conditions": [{"field": "event_id", "operator": "equals", "value": "4625"}],
            "threshold": 10,
        })
        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, 0))]
        assert len(rule.analyze(events)) == 0

    def test_dot_notation_raw_field(self):
        from threatlens.models import EventCategory, LogEvent
        rule = YamlRule({
            "name": "Raw Field Rule",
            "conditions": [{"field": "raw.EventData.SubjectUserName", "operator": "equals", "value": "admin"}],
            "threshold": 1,
        })
        event = LogEvent(
            timestamp=datetime(2025, 1, 15, 8, 30, 0),
            event_id=4625,
            source="Security",
            category=EventCategory.AUTHENTICATION,
            computer="WS-PC01",
            raw={"EventData": {"SubjectUserName": "admin"}},
        )
        assert len(rule.analyze([event])) == 1

    def test_load_from_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "rule1.yaml").write_text(
                'rules:\n  - name: "R1"\n    conditions:\n'
                '      - field: event_id\n        operator: equals\n        value: "4625"\n'
                '    threshold: 1\n',
                encoding="utf-8",
            )
            Path(tmpdir, "rule2.yml").write_text(
                'rules:\n  - name: "R2"\n    conditions:\n'
                '      - field: event_id\n        operator: equals\n        value: "4624"\n'
                '    threshold: 1\n',
                encoding="utf-8",
            )
            rules = load_yaml_rules(Path(tmpdir))
        assert len(rules) == 2

    def test_load_nonexistent_returns_empty(self):
        rules = load_yaml_rules(Path("/nonexistent/path"))
        assert rules == []

    def test_load_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("")
            f.flush()
            rules = load_yaml_rules(Path(f.name))
        assert rules == []

    def test_load_list_format(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write(
                '- name: "List Rule"\n'
                '  conditions:\n'
                '    - field: event_id\n'
                '      operator: equals\n'
                '      value: "4625"\n'
                '  threshold: 1\n'
            )
            f.flush()
            rules = load_yaml_rules(Path(f.name))
        assert len(rules) == 1

    def test_unknown_operator_is_skipped(self):
        rule = YamlRule({
            "name": "Unknown Op",
            "conditions": [{"field": "event_id", "operator": "banana", "value": "4625"}],
            "threshold": 1,
        })
        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, 0))]
        # Unknown operator is skipped (continue), so condition passes vacuously
        alerts = rule.analyze(events)
        assert len(alerts) == 1

    def test_group_by_zero_window(self):
        from datetime import timedelta
        rule = YamlRule({
            "name": "No Window",
            "description": "Group without time window",
            "severity": "medium",
            "conditions": [{"field": "event_id", "operator": "equals", "value": "4625"}],
            "group_by": "source_ip",
            "threshold": 2,
            "window_seconds": 0,
        })
        base = datetime(2025, 1, 15, 8, 30, 0)
        events = [make_failed_logon(base + timedelta(seconds=i)) for i in range(3)]
        alerts = rule.analyze(events)
        assert len(alerts) == 1


class TestSigmaRules:
    def test_sigma_rule_matching(self):
        rule = SigmaRule({
            "title": "Encoded PowerShell",
            "description": "Detects encoded PowerShell commands",
            "level": "high",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": "-encodedcommand"},
                "condition": "selection",
            },
            "tags": ["attack.execution", "attack.t1059"],
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 10, 0),
            "powershell.exe",
            "powershell.exe -nop -w hidden -encodedcommand SQBFAFgA==",
        )]
        alerts = rule.analyze(events)
        assert len(alerts) == 1
        assert "Sigma:" in alerts[0].rule_name

    def test_sigma_mitre_extraction(self):
        rule = SigmaRule({
            "title": "Test",
            "level": "high",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": "test"},
                "condition": "selection",
            },
            "tags": ["attack.execution", "attack.t1059"],
        })
        assert rule.mitre_technique == "T1059"
        assert rule.mitre_tactic == "Execution"

    def test_sigma_load_from_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "title: Test Sigma Rule\n"
                "status: experimental\n"
                "level: medium\n"
                "logsource:\n"
                "    category: process_creation\n"
                "    product: windows\n"
                "detection:\n"
                "    selection:\n"
                '        CommandLine|contains: "whoami"\n'
                "    condition: selection\n"
            )
            f.flush()
            rules = load_sigma_rules(Path(f.name))

        assert len(rules) == 1
        assert rules[0].name == "Test Sigma Rule"

    def test_sigma_not_filter(self):
        rule = SigmaRule({
            "title": "With Filter",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": "powershell"},
                "filter": {"CommandLine|contains": "legitimate"},
                "condition": "selection and not filter",
            },
        })
        # Should match — no "legitimate" in the command
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe -nop -encodedcommand ABC",
        )]
        alerts = rule.analyze(events)
        assert len(alerts) == 1

        # Should NOT match — "legitimate" is in the command
        events2 = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe legitimate-script.ps1",
        )]
        alerts2 = rule.analyze(events2)
        assert len(alerts2) == 0

    def test_sigma_wildcard_matching(self):
        rule = SigmaRule({
            "title": "Wildcard Test",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine": "*.exe*-enc*"},
                "condition": "selection",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe -encodedcommand ABC",
        )]
        alerts = rule.analyze(events)
        assert len(alerts) == 1

    def test_sigma_startswith_modifier(self):
        rule = SigmaRule({
            "title": "Startswith Test",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|startswith": "powershell"},
                "condition": "selection",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe -nop",
        )]
        alerts = rule.analyze(events)
        assert len(alerts) == 1

    def test_sigma_endswith_modifier(self):
        rule = SigmaRule({
            "title": "Endswith Test",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|endswith": ".ps1"},
                "condition": "selection",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "C:\\script.ps1",
        )]
        alerts = rule.analyze(events)
        assert len(alerts) == 1

    def test_sigma_re_modifier(self):
        rule = SigmaRule({
            "title": "Regex Test",
            "level": "high",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|re": r"reg\s+save.*sam"},
                "condition": "selection",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "reg.exe",
            "reg save HKLM\\SAM dump.hiv",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_all_modifier(self):
        rule = SigmaRule({
            "title": "All Modifier Test",
            "level": "high",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|all": ["*-nop*", "*-enc*"]},
                "condition": "selection",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe -nop -enc ABC",
        )]
        # |all requires _value_matches for each item with wildcards
        alerts = rule.analyze(events)
        assert len(alerts) == 1

    def test_sigma_1_of_selection_star(self):
        rule = SigmaRule({
            "title": "1 of selection*",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection1": {"CommandLine|contains": "powershell"},
                "selection2": {"CommandLine|contains": "nonexistent"},
                "condition": "1 of selection*",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe test",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_all_of_them(self):
        rule = SigmaRule({
            "title": "all of them",
            "level": "high",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection1": {"CommandLine|contains": "powershell"},
                "selection2": {"CommandLine|contains": "-nop"},
                "condition": "all of them",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe -nop test",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_1_of_them(self):
        rule = SigmaRule({
            "title": "1 of them",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection1": {"CommandLine|contains": "powershell"},
                "selection2": {"CommandLine|contains": "nonexistent"},
                "condition": "1 of them",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe test",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_or_condition(self):
        rule = SigmaRule({
            "title": "OR Condition",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "sel1": {"CommandLine|contains": "powershell"},
                "sel2": {"CommandLine|contains": "nonexistent"},
                "condition": "sel1 or sel2",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe test",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_and_condition(self):
        rule = SigmaRule({
            "title": "AND Condition",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "sel1": {"CommandLine|contains": "powershell"},
                "sel2": {"CommandLine|contains": "test"},
                "condition": "sel1 and sel2",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe test",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_not_condition(self):
        rule = SigmaRule({
            "title": "NOT Condition",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": "nonexistent"},
                "condition": "not selection",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe test",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_parentheses_condition(self):
        rule = SigmaRule({
            "title": "Parens",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": "powershell"},
                "condition": "(selection)",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe test",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_numeric_matching(self):
        rule = SigmaRule({
            "title": "Numeric Match",
            "level": "medium",
            "logsource": {},
            "detection": {
                "selection": {"EventID": 4625},
                "condition": "selection",
            },
        })
        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, 0))]
        assert len(rule.analyze(events)) == 1

    def test_sigma_list_value_in_selection(self):
        rule = SigmaRule({
            "title": "List Values",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": ["powershell", "cmd"]},
                "condition": "selection",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe test",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_logsource_category_filter(self):
        rule = SigmaRule({
            "title": "Network Only",
            "level": "medium",
            "logsource": {"category": "network_connection"},
            "detection": {
                "selection": {"CommandLine|contains": "powershell"},
                "condition": "selection",
            },
        })
        # Process event shouldn't match network_connection logsource
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe test",
        )]
        assert len(rule.analyze(events)) == 0

    def test_sigma_falsepositives_as_recommendation(self):
        rule = SigmaRule({
            "title": "With FP",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": "test"},
                "condition": "selection",
            },
            "falsepositives": ["Admin scripts"],
        })
        assert "Admin scripts" in rule._recommendation

    def test_sigma_load_from_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "rule1.yml").write_text(
                "title: Rule 1\nlevel: medium\nlogsource:\n  category: process_creation\n"
                "detection:\n  selection:\n    CommandLine|contains: test\n  condition: selection\n",
                encoding="utf-8",
            )
            Path(tmpdir, "rule2.yaml").write_text(
                "title: Rule 2\nlevel: high\nlogsource:\n  category: process_creation\n"
                "detection:\n  selection:\n    CommandLine|contains: hello\n  condition: selection\n",
                encoding="utf-8",
            )
            rules = load_sigma_rules(Path(tmpdir))
        assert len(rules) == 2

    def test_sigma_load_nonexistent_returns_empty(self):
        assert load_sigma_rules(Path("/nonexistent/sigma")) == []

    def test_sigma_load_skips_non_detection_docs(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False, encoding="utf-8") as f:
            f.write("title: Not a rule\nstatus: experimental\n")
            f.flush()
            rules = load_sigma_rules(Path(f.name))
        assert len(rules) == 0

    def test_sigma_multi_document_yaml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False, encoding="utf-8") as f:
            f.write(
                "title: Rule A\nlevel: medium\nlogsource:\n  category: process_creation\n"
                "detection:\n  selection:\n    CommandLine|contains: test\n  condition: selection\n"
                "---\n"
                "title: Rule B\nlevel: high\nlogsource:\n  category: process_creation\n"
                "detection:\n  selection:\n    CommandLine|contains: hello\n  condition: selection\n"
            )
            f.flush()
            rules = load_sigma_rules(Path(f.name))
        assert len(rules) == 2

    def test_sigma_selection_as_list_of_dicts(self):
        rule = SigmaRule({
            "title": "List Selection",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": [
                    {"CommandLine|contains": "powershell"},
                    {"CommandLine|contains": "cmd"},
                ],
                "condition": "selection",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe test",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_startswith_list(self):
        rule = SigmaRule({
            "title": "Startswith List",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|startswith": ["cmd", "powershell"]},
                "condition": "selection",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe test",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_endswith_list(self):
        rule = SigmaRule({
            "title": "Endswith List",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|endswith": [".exe", ".ps1"]},
                "condition": "selection",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "C:\\script.exe",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_re_list(self):
        rule = SigmaRule({
            "title": "Regex List",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|re": [r"nonexist", r"power.*"]},
                "condition": "selection",
            },
        })
        events = [make_process_event(
            datetime(2025, 1, 15, 9, 0, 0),
            "powershell.exe",
            "powershell.exe test",
        )]
        assert len(rule.analyze(events)) == 1

    def test_sigma_event_data_field_lookup(self):
        from threatlens.models import EventCategory, LogEvent
        rule = SigmaRule({
            "title": "EventData Lookup",
            "level": "medium",
            "logsource": {},
            "detection": {
                "selection": {"SubjectLogonId": "0x3e7"},
                "condition": "selection",
            },
        })
        event = LogEvent(
            timestamp=datetime(2025, 1, 15, 8, 30, 0),
            event_id=4625,
            source="Security",
            category=EventCategory.AUTHENTICATION,
            computer="WS-PC01",
            raw={"EventData": {"SubjectLogonId": "0x3e7"}},
        )
        assert len(rule.analyze([event])) == 1

    def test_sigma_value_matches_list(self):
        from threatlens.rules.sigma_loader import _value_matches
        assert _value_matches("test", ["test", "other"]) is True
        assert _value_matches("nope", ["test", "other"]) is False

    def test_sigma_value_matches_none(self):
        from threatlens.rules.sigma_loader import _value_matches
        assert _value_matches(None, "test") is False


class TestSigmaIntegration:
    """Integration tests using realistic Sigma rules against sample data."""

    def _load_sample_events(self):
        """Load events from the sample security log."""
        from threatlens.parsers import load_events
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return []
        return load_events(sample)

    def test_sigma_rules_load_from_samples_dir(self):
        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)
        assert len(rules) == 7
        names = {r.name for r in rules}
        assert "Suspicious Encoded PowerShell Command Line" in names
        assert "SAM Registry Hive Dump" in names
        assert "Certutil Download Cradle" in names

    def test_encoded_powershell_sigma_detects(self):
        events = self._load_sample_events()
        if not events:
            return
        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)
        ps_rule = next(r for r in rules if "PowerShell" in r.name)
        alerts = ps_rule.analyze(events)
        assert len(alerts) >= 1
        assert any("Sigma:" in a.rule_name for a in alerts)

    def test_sam_dump_sigma_detects(self):
        events = self._load_sample_events()
        if not events:
            return
        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)
        sam_rule = next(r for r in rules if "SAM" in r.name)
        alerts = sam_rule.analyze(events)
        assert len(alerts) >= 1
        assert alerts[0].severity.value == "critical"

    def test_certutil_sigma_detects(self):
        events = self._load_sample_events()
        if not events:
            return
        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)
        cert_rule = next(r for r in rules if "Certutil" in r.name)
        alerts = cert_rule.analyze(events)
        assert len(alerts) >= 1

    def test_all_sigma_rules_against_sample_data(self):
        """Run all sample Sigma rules against sample data — integration smoke test."""
        events = self._load_sample_events()
        if not events:
            return
        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)
        total_alerts = []
        for rule in rules:
            total_alerts.extend(rule.analyze(events))
        # The sample data contains encoded PS, SAM dump, and certutil — all 3 should fire
        assert len(total_alerts) >= 3
        severities = {a.severity.value for a in total_alerts}
        assert "critical" in severities
        assert "high" in severities

    def test_sigma_rules_against_mixed_data(self):
        """Run against mixed enterprise log — should detect the embedded attacks."""
        from threatlens.parsers import load_events
        sample = Path(__file__).parent.parent / "sample_data" / "mixed_enterprise_log.json"
        if not sample.exists():
            return
        events = load_events(sample)
        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)
        total_alerts = []
        for rule in rules:
            total_alerts.extend(rule.analyze(events))
        # Mixed data also contains encoded PS, SAM dump, certutil
        assert len(total_alerts) >= 3


class TestSigmaCorpusValidation:
    """Validate the Sigma loader against an expanded corpus of 7 rules
    covering diverse condition types: simple selection, OR, AND NOT, |all,
    |endswith, |startswith, |contains, and 1/all of patterns."""

    def test_all_corpus_rules_load(self):
        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)
        assert len(rules) == 7
        names = {r.name for r in rules}
        assert "PsExec Service Execution" in names
        assert "Scheduled Task Created via Command Line" in names
        assert "Windows Defender Disabled via Registry" in names
        assert "Suspicious Sudo Command Execution" in names

    def test_psexec_detection_or_condition(self):
        """Test OR condition: selection1 or selection2."""
        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)
        rule = next(r for r in rules if "PsExec" in r.name)

        # Match via selection1 (Image endswith)
        event1 = make_process_event(
            datetime(2025, 1, 15, 10, 0, 0),
            process=r"C:\Tools\PsExec.exe",
            cmd="PsExec.exe \\\\server01 cmd.exe",
        )
        alerts1 = rule.analyze([event1])
        assert len(alerts1) >= 1

        # Match via selection2 (CommandLine contains psexec)
        event2 = make_process_event(
            datetime(2025, 1, 15, 10, 0, 0),
            process="cmd.exe",
            cmd="psexec /accepteula \\\\dc01 whoami",
        )
        alerts2 = rule.analyze([event2])
        assert len(alerts2) >= 1

    def test_defender_disabled_and_not_filter(self):
        """Test 'selection and not filter' condition."""
        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)
        rule = next(r for r in rules if "Defender" in r.name)

        # Should match — non-SYSTEM user modifying defender registry
        from threatlens.models import EventCategory, LogEvent
        event = LogEvent(
            timestamp=datetime(2025, 1, 15, 10, 0, 0),
            event_id=13,
            source="Sysmon",
            category=EventCategory.REGISTRY,
            computer="WS-01",
            raw={"EventID": 13},
            username="attacker",
            command_line="reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /v DisableAntiSpyware /t REG_DWORD /d 1",
        )
        alerts = rule.analyze([event])
        assert len(alerts) >= 1

        # Should NOT match — SYSTEM user (filtered out)
        event_system = LogEvent(
            timestamp=datetime(2025, 1, 15, 10, 0, 0),
            event_id=13,
            source="Sysmon",
            category=EventCategory.REGISTRY,
            computer="WS-01",
            raw={"EventID": 13},
            username="NT AUTHORITY\\SYSTEM",
            command_line="reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /v DisableAntiSpyware /t REG_DWORD /d 1",
        )
        alerts_system = rule.analyze([event_system])
        assert len(alerts_system) == 0

    def test_schtask_persistence(self):
        """Test combined endswith + contains selection."""
        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)
        rule = next(r for r in rules if "Scheduled Task" in r.name)

        event = make_process_event(
            datetime(2025, 1, 15, 10, 0, 0),
            process=r"C:\Windows\System32\schtasks.exe",
            cmd='schtasks.exe /create /tn "Persist" /tr "C:\\evil.exe" /sc ONLOGON',
        )
        alerts = rule.analyze([event])
        assert len(alerts) >= 1
        assert alerts[0].mitre_technique == "T1053.005"

    def test_sudo_priv_esc(self):
        """Test contains modifier with list values."""
        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)
        rule = next(r for r in rules if "Sudo" in r.name)

        event = make_process_event(
            datetime(2025, 1, 15, 10, 0, 0),
            process="bash",
            cmd="sudo su -",
        )
        alerts = rule.analyze([event])
        assert len(alerts) >= 1
        assert alerts[0].mitre_technique == "T1548.003"

    def test_no_false_positives_clean_events(self):
        """All 7 rules should produce zero alerts on benign activity."""
        from threatlens.models import EventCategory, LogEvent

        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)

        benign_events = [
            LogEvent(
                timestamp=datetime(2025, 1, 15, 8, 0, 0),
                event_id=4624,
                source="Security",
                category=EventCategory.AUTHENTICATION,
                computer="WS-01",
                raw={"EventID": 4624},
                username="jdoe",
                command_line="explorer.exe",
                process_name="explorer.exe",
            ),
            LogEvent(
                timestamp=datetime(2025, 1, 15, 8, 5, 0),
                event_id=4688,
                source="Security",
                category=EventCategory.PROCESS,
                computer="WS-01",
                raw={"EventID": 4688},
                username="jdoe",
                command_line="notepad.exe C:\\docs\\readme.txt",
                process_name=r"C:\Windows\System32\notepad.exe",
            ),
        ]

        total_alerts = []
        for rule in rules:
            total_alerts.extend(rule.analyze(benign_events))
        assert len(total_alerts) == 0

    def test_corpus_mitre_coverage(self):
        """Verify that the corpus covers multiple MITRE tactics."""
        sigma_dir = Path(__file__).parent / "sigma_samples"
        rules = load_sigma_rules(sigma_dir)
        tactics = {r.mitre_tactic for r in rules if r.mitre_tactic}
        # Should cover at least: execution, credential_access, defense_evasion,
        # lateral_movement, persistence, privilege_escalation
        assert len(tactics) >= 4
