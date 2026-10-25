"""Print the results tables for docs/simulator-check.md, from the recorded fixtures.

    python -m simulator_check.report

A case counts as agreeing only when tests/simulator_fixtures/verdicts.json doesn't list it.
"""

import json
from typing import Any

from simulator_check import FIXTURE_DIR, outcomes
from simulator_check.cases import NotExpressible, load_cases, requests_for

# The doc's parts, each with the groups of cases in it, in order.
PARTS = [
    ("Calibration", [
        "calibration_aws_example", "calibration_absent_keys", "calibration_role_callers",
    ]),
    ("Part 1. Wildcards and colons", ["wildcards_and_colons"]),
    ("Part 2. ForAllValues:StringNotLike", ["for_all_values_string_not_like"]),
    ("Part 3. A `*` grant when the boundary doesn't allow", ["star_grant_and_boundary"]),
    ("Part 4. The other refusals", [
        "variables_without_a_value", "variables_with_several_values", "variables_with_wildcards",
        "bool_with_a_variable", "dates_without_a_time_zone", "ip_ranges",
        "short_arns_in_arn_operators", "several_values_without_a_set_operator", "empty_values",
        "for_any_value_if_exists", "set_operator_on_null", "operator_name_case",
        "role_principal_case", "not_principal",
    ]),
    ("Part 5. The review's other open questions", [
        "list_all_my_buckets", "scp_allow_statements", "scp_short_arn",
    ]),
    ("Judgment call", ["set_operators_on_numbers"]),
    ("Part 6. Existing scenarios", ["scenarios"]),
]


def main() -> int:
    fixtures = [json.loads(path.read_text()) for path in sorted(FIXTURE_DIR.glob("*/*.json"))]
    verdicts = json.loads((FIXTURE_DIR / "verdicts.json").read_text())
    by_group: dict[str, list[dict[str, Any]]] = {}
    for fixture in fixtures:
        by_group.setdefault(fixture["case"].partition("/")[0], []).append(fixture)

    print(f"Findings: {json.dumps(verdicts['findings'])}\n")
    for title, groups in PARTS:
        rows = [fixture for group in groups for fixture in by_group.get(group, [])]
        if title == "Calibration":
            rows += [f for f in by_group.get("scenarios", []) if f.get("documented")]
        if rows:
            print(f"### {title}\n")
            print(_table(rows, verdicts["cases"]))
    counts: dict[str, int] = {}
    for fixture in fixtures:
        verdict = verdicts["cases"].get(fixture["case"], {}).get("verdict", "agrees")
        counts[verdict] = counts.get(verdict, 0) + 1
    print("Verdicts: " + ", ".join(f"{verdict} {count}" for verdict, count in sorted(counts.items())))
    print("\n### Can't express\n")
    print("| Case | Why |\n|---|---|")
    for case in load_cases():
        try:
            requests_for(case)
        except NotExpressible as exc:
            print(f"| `{case.id}` | {_cell(str(exc))} |")
    return 0


def _table(fixtures: list[dict[str, Any]], listed: dict[str, Any]) -> str:
    lines = [
        "| Case | Analyzer | Simulator | Verdict | Missing context values | Matched | Details |",
        "|---|---|---|---|---|---|---|",
    ]
    for fixture in fixtures:
        ours = outcomes.ours(fixture["simulate"]["request"], fixture["absent"]).label
        theirs = outcomes.aws(fixture).label
        verdict = listed.get(fixture["case"], {}).get("verdict", "agrees")
        details = [f"{name}: {value}" for name, value in outcomes.details(fixture).items()]
        if fixture.get("documented"):
            details.insert(0, f"documented: {fixture['documented']['decision']}")
        cells = [
            f"`{fixture['case']}`", ours, theirs, verdict,
            ", ".join(outcomes.missing_context_values(fixture)) or "-",
            ", ".join(outcomes.matched_sources(fixture)) or "-",
            "; ".join(details) or "-",
        ]
        lines.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
    return "\n".join(lines) + "\n"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


if __name__ == "__main__":
    raise SystemExit(main())
