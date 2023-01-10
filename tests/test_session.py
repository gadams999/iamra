"""Test cases for the __main__ module."""
# import pytest

from iamra import Credentials


def test_default_session() -> None:
    """Create a default Credentials object and verify default values are valid."""
    session = Credentials(
        region="us-east-1",
        cert_filename="tests/assets/client_secp384r1.pem",
        private_key_filename="tests/assets/client_secp384r1.key",
        duration=3600,
        profile_arn="arn:aws:rolesanywhere:us-east-1:123456789012:profile/ca9f7056-0470-4851-962e-bea4e5855b47",
        role_arn="arn:aws:iam::123456789012:role/test_roles_anywhere",
        session_name="test_session",
        trust_anchor_arn="arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/e7f288d3-58f8-467f-bf7a-085c86905cdf",
    )
    assert session.region == "us-east-1"
    assert session.duration == 3600
    assert (
        session.profile_arn
        == "arn:aws:rolesanywhere:us-east-1:123456789012:profile/ca9f7056-0470-4851-962e-bea4e5855b47"
    )
    assert session.role_arn == "arn:aws:iam::123456789012:role/test_roles_anywhere"
    assert session.session_name == "test_session"
    assert (
        session.trust_anchor_arn
        == "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/e7f288d3-58f8-467f-bf7a-085c86905cdf"
    )
    assert session.passphrase is None
    assert session.credentials == {
        "accessKeyId": "",
        "expiration": "",
        "secretAccessKey": "",
        "sessionToken": "",
    }


# test with passphrase
# test with ECC - good
# test with DSA - bad
