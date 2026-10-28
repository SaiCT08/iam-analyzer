import pytest

from iam_analyzer.condition_keys import GLOBAL_KEYS_PAGE, KNOWN, values_of


def test_keys_ignore_case():
    assert values_of("AWS:multifactorauthpresent").key == "aws:MultiFactorAuthPresent"
    assert values_of("aws:SourceIp") is None


@pytest.mark.parametrize("known", KNOWN, ids=[known.key for known in KNOWN])
def test_every_key_quotes_its_availability_on_awss_page(known):
    assert known.link.startswith(f"{GLOBAL_KEYS_PAGE}#condition-keys-")
    assert known.quote.startswith("This key is")
    # Only Bool keys so far: both values, and absent only where AWS says a request can omit it.
    assert {"true", "false"} <= set(known.values) <= {"true", "false", None}


def test_aws_checks_mfa_for_a_role_when_its_assumed():
    mfa = values_of("aws:MultiFactorAuthPresent")
    assert mfa.checked_when_assumed and mfa.role_term == "MFA"
    assert mfa.role_quote.startswith("The temporary credentials returned by AssumeRole do not ")
    assert mfa.role_link.startswith("https://docs.aws.amazon.com/IAM/latest/UserGuide/")
    # The quote, its link and the term come together, and only MFA has them so far.
    for known in KNOWN:
        role_fields = (known.role_quote, known.role_link, known.role_term)
        if known is mfa:
            assert None not in role_fields
        else:
            assert role_fields == (None, None, None) and not known.checked_when_assumed


def test_mfa_can_be_absent_and_tls_cannot():
    assert values_of("aws:MultiFactorAuthPresent").values == ("true", "false", None)
    assert values_of("aws:SecureTransport").values == ("true", "false")
    assert values_of("aws:ViaAWSService").values == ("true", "false")
