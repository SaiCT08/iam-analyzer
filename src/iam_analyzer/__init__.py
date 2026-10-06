"""AWS IAM effective-permissions analyzer."""

from iam_analyzer.evaluator import evaluate
from iam_analyzer.loader import load_policy, load_policy_file, parse_policy
from iam_analyzer.models import Decision, EvaluationResult, Policy, Request, Statement

__all__ = [
    "Decision",
    "EvaluationResult",
    "Policy",
    "Request",
    "Statement",
    "evaluate",
    "load_policy",
    "load_policy_file",
    "parse_policy",
]
