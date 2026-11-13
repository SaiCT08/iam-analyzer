"""The README's examples: every `iam-analyzer check` command it shows with its output, the report
excerpt at its top, and the example files it points to."""

import re
import shlex
from pathlib import Path

import pytest

from iam_analyzer.cli import main
from simulator_check import safety_problems

REPO = Path(__file__).parent.parent
README = (REPO / "README.md").read_text(encoding="utf-8")
GOLDEN = Path(__file__).parent / "golden" / "anycompany_report.md"
FENCE = re.compile(r"^```(\w*)\n(.*?)^```$", re.S | re.M)


def arguments(command):
    """A shell command's arguments, with its line continuations joined."""
    return shlex.split(command.replace("\\\n", " "))


def shown_checks():
    """Each sh block that runs `iam-analyzer check`, with the plain block right after it: the
    output the README shows. Only a blank line, or "Output:", may come between them."""
    blocks = list(FENCE.finditer(README))
    shown = []
    for block, after in zip(blocks, blocks[1:]):
        between = README[block.end():after.start()].strip()
        if (block.group(1) == "sh" and block.group(2).startswith("iam-analyzer check")
                and after.group(1) == "" and between in ("", "Output:")):
            shown.append((block.group(2), after.group(2)))
    return shown


CHECKS = shown_checks()


def name(command):
    args = arguments(command)
    who = args[args.index("--principal") + 1] if "--principal" in args else "policies"
    return f"{who} {args[args.index('--action') + 1]}"


def test_the_readme_shows_its_check_examples():
    # A change to the README's layout mustn't quietly leave its examples untested.
    assert len(CHECKS) >= 15


@pytest.mark.parametrize("command, output", CHECKS,
                         ids=[f"{i} {name(command)}" for i, (command, _) in enumerate(CHECKS)])
def test_a_check_example_prints_what_the_readme_shows(command, output, capsys, monkeypatch):
    monkeypatch.chdir(REPO)
    main(arguments(command)[1:])
    out, err = capsys.readouterr()
    assert out + err == output


def test_the_report_excerpt_is_part_of_the_anycompany_report():
    excerpt = FENCE.search(README.split("\n## A report\n", 1)[1]).group(2)
    assert excerpt in GOLDEN.read_text(encoding="utf-8")


@pytest.mark.parametrize("path", sorted((REPO / "examples").rglob("*.json")),
                         ids=lambda path: str(path.relative_to(REPO)))
def test_the_example_files_use_only_aws_example_account_ids(path):
    assert safety_problems(path.read_text(encoding="utf-8")) == []
