"""Record the IAM policy simulator's answers to the cases. Needs boto3, and calls AWS.

    python -m simulator_check.record --dry-run                      # the requests, without AWS
    python -m simulator_check.record --only calibration_aws_example  # a group, or GROUP/CASE
    python -m simulator_check.record                                # every case not yet recorded

boto3 finds the iam-simulator profile's access key itself: this module never reads, prints or logs
credentials, and it leaves botocore's logging off, because that would print the signed request.

For each case it asks GetContextKeysForCustomPolicy which keys the policies use, checks that the
case gives each one or marks it absent, then asks SimulateCustomPolicy. It saves both requests and
AWS's raw responses as the case's fixture, once the fixture passes `safety_problems`. At the first
problem it stops, and prints only what is safe to print: never an AWS error message.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any

from simulator_check import FIXTURE_DIR, outcomes, safety_problems
from simulator_check.cases import SCENARIOS, Case, NotExpressible, Requests, load_cases, requests_for

PROFILE = "iam-simulator"
# AWS's errors that answer the question a case asks, such as a policy AWS won't accept. They are
# recorded like any other answer.
ANSWERS = ("InvalidInput", "MalformedPolicyDocument", "PolicyEvaluation")
# AWS's errors that mean the credentials didn't work, besides AccessDenied*.
CREDENTIAL_ERRORS = (
    "InvalidClientTokenId", "SignatureDoesNotMatch", "ExpiredToken", "UnrecognizedClientException",
    "InvalidAccessKeyId", "AuthFailure", "MissingAuthenticationToken",
)
METHODS = {
    "GetContextKeysForCustomPolicy": "get_context_keys_for_custom_policy",
    "SimulateCustomPolicy": "simulate_custom_policy",
}


class Stop(Exception):
    """Stops the run. The message is safe to print: it never repeats what AWS said."""


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        client = None
        for case in _select(load_cases(), args.only):
            try:
                requests = requests_for(case)
            except NotExpressible as exc:
                print(f"{case.id} | can't express: {exc}")
                continue
            ours = outcomes.ours(requests.simulate, requests.absent)
            _check_scenario(case, ours)
            if args.dry_run:
                print(json.dumps({"case": case.id, "analyzer": ours.label,
                                  "absent": list(requests.absent), "simulate": requests.simulate},
                                 indent=2))
                continue
            path = FIXTURE_DIR / f"{case.id}.json"
            if path.exists() and not args.force:
                print(f"{case.id} | already recorded")
                continue
            client = client or _Client(args.profile)
            fixture = _record(client, case, requests)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(_summary(fixture, ours))
    except Stop as exc:
        print(f"stopped: {exc}", file=sys.stderr)
        return 1
    return 0


class _Client:
    """boto3's IAM client for the profile, keeping the raw body of its latest response."""

    def __init__(self, profile: str) -> None:
        try:
            import boto3
            from botocore.config import Config
            from botocore.exceptions import BotoCoreError
        except ImportError:
            raise Stop('boto3 isn\'t installed: pip install -e ".[simulator]"') from None
        try:
            session = boto3.Session(profile_name=profile)
            config = Config(retries={"mode": "standard", "max_attempts": 5})
            self.iam = session.client("iam", region_name="us-east-1", config=config)
        except BotoCoreError as exc:
            raise Stop(f"the AWS profile {profile!r} didn't work ({type(exc).__name__})") from None
        self.raw: dict[str, Any] | None = None
        # botocore calls this with each response, error responses included, before it raises.
        self.iam.meta.events.register("after-call.iam", self._keep_raw)

    def _keep_raw(self, http_response: Any, **kwargs: Any) -> None:
        self.raw = {"date": http_response.headers.get("date"), "body": http_response.text}

    def call(self, operation: str, request: dict[str, Any]) -> dict[str, Any]:
        """Call `operation`. AWS's answer, or the error that answers the case, as a fixture entry."""
        from botocore.exceptions import BotoCoreError, ClientError

        self.raw = None
        try:
            response = getattr(self.iam, METHODS[operation])(**request)
            error, metadata = None, response["ResponseMetadata"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in CREDENTIAL_ERRORS or code.startswith("AccessDenied"):
                raise Stop(f"the AWS credentials didn't work ({code})") from None
            if code not in ANSWERS:
                raise Stop(f"AWS answered {operation} with {code or 'an unnamed error'}") from None
            response, error = None, exc.response["Error"]
            metadata = exc.response.get("ResponseMetadata", {})
        except BotoCoreError as exc:
            raise Stop(f"{operation} failed ({type(exc).__name__})") from None
        if self.raw is None:
            raise Stop(f"botocore didn't pass on the raw response to {operation}")
        return {
            "request": request,
            "response": response,
            "error": error,
            "request_id": metadata.get("RequestId"),
            "http_date": self.raw["date"],
            "raw_body": self.raw["body"],
        }


def _record(client: _Client, case: Case, requests: Requests) -> dict[str, Any]:
    context_keys = [client.call("GetContextKeysForCustomPolicy", requests.context_keys)]
    if context_keys[0]["error"] is not None:
        # One call per policy, so that a policy AWS won't read doesn't hide the others' keys.
        context_keys += [
            client.call("GetContextKeysForCustomPolicy", {"PolicyInputList": [document]})
            for document in requests.context_keys["PolicyInputList"]
        ]
    d = case.definition
    fixture: dict[str, Any] = {
        "case": case.id,
        "source": case.source,
        "question": d.get("question"),
        "description": d.get("description"),
        "readings": d.get("readings"),
        "documented": d.get("documented"),
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "absent": list(requests.absent),
        "context_keys": context_keys,
        "simulate": None,
    }
    given = {entry["ContextKeyName"].casefold() for entry in requests.simulate.get("ContextEntries", [])}
    given |= {key.casefold() for key in requests.absent}
    lacking = [key for key in outcomes.listed_keys(fixture) if key.casefold() not in given]
    if lacking:
        raise Stop(f"{case.id}: the case doesn't give {', '.join(lacking)}, which AWS says a policy uses")
    fixture["simulate"] = client.call("SimulateCustomPolicy", requests.simulate)
    _check_answer(fixture)
    problems = safety_problems(json.dumps(fixture, default=str))
    if problems:
        raise Stop(f"{case.id}: not saved, because it contains {' and '.join(problems)}")
    return fixture


def _check_answer(fixture: dict[str, Any]) -> None:
    """The answer must be complete, and AWS must have had every key the case gives."""
    call = fixture["simulate"]
    if call["error"] is not None:
        return
    if call["response"].get("IsTruncated") or len(call["response"]["EvaluationResults"]) != 1:
        raise Stop(f"{fixture['case']}: AWS's answer isn't one complete result")
    absent = {key.casefold() for key in fixture["absent"]}
    unexpected = [key for key in outcomes.missing_context_values(fixture) if key.casefold() not in absent]
    if unexpected:
        raise Stop(f"{fixture['case']}: AWS says it lacked {', '.join(unexpected)}, which the case gives")


def _check_scenario(case: Case, ours: outcomes.Outcome) -> None:
    """A scenario must keep its answer when it is turned into a request, or the converter changed
    the question."""
    if case.group == SCENARIOS and ours.label != case.definition["expected"]:
        raise Stop(
            f"{case.id}: the request gives {ours.label}, but the scenario expects "
            f"{case.definition['expected']}"
        )


def _select(cases: list[Case], only: list[str] | None) -> list[Case]:
    if not only:
        return cases
    unknown = [name for name in only if not any(name in (case.id, case.group) for case in cases)]
    if unknown:
        raise Stop(f"no case or group named {', '.join(unknown)}")
    return [case for case in cases if case.id in only or case.group in only]


def _summary(fixture: dict[str, Any], ours: outcomes.Outcome) -> str:
    parts = [fixture["case"], f"analyzer {ours.label}", f"simulator {outcomes.aws(fixture).label}"]
    if fixture["documented"]:
        parts.append(f"documented {fixture['documented']['decision']}")
    parts.append(f"missing {', '.join(outcomes.missing_context_values(fixture)) or '-'}")
    parts.append(f"matched {', '.join(outcomes.matched_sources(fixture)) or '-'}")
    parts += [f"{name} {value}" for name, value in outcomes.details(fixture).items()]
    return " | ".join(parts)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m simulator_check.record",
        description="Record AWS's IAM policy simulator's answers to the cases, as fixtures.",
    )
    parser.add_argument("--profile", default=PROFILE, help=f"the AWS profile (default {PROFILE})")
    parser.add_argument("--only", nargs="+", metavar="GROUP[/CASE]", help="record only these")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print the requests and the analyzer's answers, without calling AWS",
    )
    parser.add_argument("--force", action="store_true", help="replace fixtures that already exist")
    return parser


if __name__ == "__main__":
    sys.exit(main())
