"""redact() strips anything that looks like a secret before text leaves the host (QA-PR-01)."""

import pytest

from devsecops.llm import REDACTED, SECRET_PATTERNS, redact

# Made-up values in the shape of each kind of secret. None of them is real.
SECRETS = {
    "private_key_block": (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1L7VLPHCgcBIjt\n"
        "-----END RSA PRIVATE KEY-----"
    ),
    "openrouter_key": "sk-or-v1-0123456789abcdef0123456789abcdef",
    "anthropic_key": "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv",
    "github_token": "ghp_" + "Z9y8X7w6" * 5,
    "github_pat": "github_pat_11ABCDEFG0123456789_abcdefghijklmnop",
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
}


def test_every_pattern_has_a_test():
    assert {p.name for p in SECRET_PATTERNS} == set(SECRETS) | {
        "bearer_token",
        "secret_assignment",
    }


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_qa_pr_01_secret_is_redacted(name):
    secret = SECRETS[name]
    text = f"before {secret} after"
    out = redact(text)
    assert secret not in out
    assert REDACTED in out
    assert out.startswith("before ") and out.endswith(" after")


def test_qa_pr_01_bearer_token_keeps_the_word_bearer():
    out = redact("Authorization: Bearer abc.def-123_456")
    assert out == f"Authorization: Bearer {REDACTED}"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('password = "hunter2hunter2"', f'password = "{REDACTED}"'),
        ("DB_PASSWORD=s3cr3tvalue", f"DB_PASSWORD={REDACTED}"),
        ("api_key: 'abcd1234efgh'", f"api_key: '{REDACTED}'"),
        ("Possible hardcoded password: 'letmein99'", f"Possible hardcoded password: '{REDACTED}'"),
        ('{"token": "zzzz9999"}', f'{{"token": "{REDACTED}"}}'),
        ("SECRET_KEY=abcdefgh", f"SECRET_KEY={REDACTED}"),
        (
            "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
            f"token={REDACTED}",
        ),
        ("password=hunter22.", f"password={REDACTED}"),  # the full stop goes too
    ],
)
def test_qa_pr_01_secret_assignment_keeps_the_name(text, expected):
    assert redact(text) == expected


def test_qa_pr_01_private_key_cut_off_before_its_end_is_still_redacted():
    out = redact("key: -----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASC")
    assert "MIIEvQ" not in out


@pytest.mark.parametrize(
    "text",
    [
        "B602: subprocess call with shell=True identified, security issue.",
        "test_list_notes failed: assert 2 == 3",
        "sample_app/app/main.py",
        "Use of insecure MD5 hash function for share tokens.",
        "requests 2.19.0 has GHSA-x84v-xcm2-53pg",
        "the password field is required",
        "token budget exceeded",
        'return {"token": share_token(note_id)}',
        "password = get_password()",
        'TOKEN = os.environ.get("CONTROL_API_TOKEN", "")',
        'token = os.environ["GITHUB_TOKEN"]',
        "api_key = settings.api_key",
    ],
)
def test_normal_text_is_left_alone(text):
    assert redact(text) == text


def test_redacting_twice_changes_nothing_more():
    once = redact(f"token={SECRETS['openrouter_key']} and password=hunter22")
    assert redact(once) == once
