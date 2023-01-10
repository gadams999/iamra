"""Test cases for the __main__ module."""
# import pytest

from iamra import Credentials
from iamra import SessionResponse


# @pytest.fixture
def test_new_credentials() -> None:
    """Test that we can create new credential object."""
    assert (
        Credentials(
            region="us-east-1",
            cert_filename="tests/assets/client_secp384r1.pem",
            private_key_filename="tests/assets/client_secp384r1.key",
            duration=3600,
            profile_arn="arn:aws:iam00000056789012:user/test",
            role_arn="arn:aws:iam00000056789012:role/test",
            session_name="test_session",
            trust_anchor_arn="arn:aws:iam00000056789012:role/test",
        )
        == SessionResponse
    )
