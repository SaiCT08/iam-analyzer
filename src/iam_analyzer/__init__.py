"""AWS IAM effective-permissions analyzer."""

from iam_analyzer.account import Account, load_account_file, parse_account
from iam_analyzer.evaluator import evaluate
from iam_analyzer.loader import load_policy, load_policy_file, parse_policy
from iam_analyzer.models import (
    Decision,
    EvaluationResult,
    Layer,
    Policy,
    PolicyType,
    Request,
    Statement,
)

__all__ = [
    "Account",
    "Decision",
    "EvaluationResult",
    "Layer",
    "Policy",
    "PolicyType",
    "Request",
    "Statement",
    "evaluate",
    "load_account_file",
    "load_policy",
    "load_policy_file",
    "parse_account",
    "parse_policy",
]
