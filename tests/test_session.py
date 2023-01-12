"""Test cases for the iamra module."""
from time import time

import pytest

from iamra import Credentials
from iamra.session import EncryptionAlgorithmError


valid_region = "us-east-1"
profile_arn = (
    "arn:aws:rolesanywhere:us-east-1:123456789012:"
    + "profile/ca9f7056-0470-4851-962e-bea4e5855b47"
)
role_arn = "arn:aws:iam::123456789012:role/test_roles_anywhere"
trust_anchor_arn = (
    "arn:aws:rolesanywhere:us-east-1:123456789012:"
    + "trust-anchor/e7f288d3-58f8-467f-bf7a-085c86905cdf"
)

valid_session_response = {
    "credentialSet": [
        {
            "assumedRoleUser": {
                "arn": "test_assumed_user_arn",
                "assumedRoleId": "test_role_id",
            },
            "credentials": {
                "accessKeyId": "test_access_key_id",
                "expiration": time(),
                "secretAccessKey": "test_secret_access_key",
                "sessionToken": "test_session_token",
            },
            "packedPolicySize": 12345,
            "roleArn": "test_role_arn",
            "sourceIdentity": "test_source_identity",
        }
    ],
    "subjectArn": "test_subject_arn",
}


def test_default_session() -> None:
    """Create a default Credentials object and verify default values are valid.

    Full check of set attributes.
    """
    session = Credentials(
        region=valid_region,
        cert_filename="tests/assets/client_secp384r1.pem",
        private_key_filename="tests/assets/client_secp384r1.key",
        duration=3600,
        profile_arn=profile_arn,
        role_arn=role_arn,
        session_name="test_session",
        trust_anchor_arn=trust_anchor_arn,
    )
    assert session.region == "us-east-1"
    assert session.duration == 3600
    assert session.profile_arn == profile_arn
    assert session.role_arn == role_arn
    assert session.session_name == "test_session"
    assert session.trust_anchor_arn == trust_anchor_arn
    assert session.credentials == {
        "accessKeyId": "",
        "expiration": "",
        "secretAccessKey": "",
        "sessionToken": "",
    }


def test_session_rsa() -> None:
    """Verify RSA certificate."""
    session = Credentials(
        region=valid_region,
        cert_filename="tests/assets/client_rsa2048.pem",
        private_key_filename="tests/assets/client_rsa2048.key",
        duration=3600,
        profile_arn=profile_arn,
        role_arn=role_arn,
        session_name="test_session",
        trust_anchor_arn=trust_anchor_arn,
    )
    assert session.credentials == {
        "accessKeyId": "",
        "expiration": "",
        "secretAccessKey": "",
        "sessionToken": "",
    }


def test_session_ecc_good_passphrase() -> None:
    """Verify EC certificate and valid passphrase."""
    session = Credentials(
        region=valid_region,
        cert_filename="tests/assets/client_secp384r1_passphrase.pem",
        private_key_filename="tests/assets/client_secp384r1_passphrase.key",
        duration=3600,
        profile_arn=profile_arn,
        role_arn=role_arn,
        session_name="test_session",
        trust_anchor_arn=trust_anchor_arn,
        passphrase=b"foobar",
    )
    assert session.credentials == {
        "accessKeyId": "",
        "expiration": "",
        "secretAccessKey": "",
        "sessionToken": "",
    }


def test_session_ecc_bad_passphrase() -> None:
    """Verify EC certificate and valid passphrase."""
    with pytest.raises(ValueError, match=r"Bad decrypt. Incorrect password?"):
        Credentials(
            region=valid_region,
            cert_filename="tests/assets/client_secp384r1_passphrase.pem",
            private_key_filename="tests/assets/client_secp384r1_passphrase.key",
            duration=3600,
            profile_arn=profile_arn,
            role_arn=role_arn,
            session_name="test_session",
            trust_anchor_arn=trust_anchor_arn,
            passphrase=b"thisIsNotAGoodPassphrase",
        )


def test_session_dsa() -> None:
    """Verify DSA certificate and value error."""
    with pytest.raises(
        EncryptionAlgorithmError,
        match=(
            r"Unknown private key type, only RSA and EC keys "
            + r"are supported for IAM Roles Anywhere"
        ),
    ):
        Credentials(
            region=valid_region,
            cert_filename="tests/assets/client_dsa2048.pem",
            private_key_filename="tests/assets/client_dsa2048.key",
            duration=3600,
            profile_arn=profile_arn,
            role_arn=role_arn,
            session_name="test_session",
            trust_anchor_arn=trust_anchor_arn,
        )


def test_session_invalid_cert_file() -> None:
    """Verify certificate file not found."""
    with pytest.raises(
        FileNotFoundError,
        match=r"Certificate tests/assets/cert_file_doesnt_exist.pem not found",
    ):
        Credentials(
            region=valid_region,
            cert_filename="tests/assets/cert_file_doesnt_exist.pem",
            private_key_filename="tests/assets/client_rsa2048.key",
            duration=3600,
            profile_arn=profile_arn,
            role_arn=role_arn,
            session_name="test_session",
            trust_anchor_arn=trust_anchor_arn,
        )


def test_session_invalid_privatekey_file() -> None:
    """Verify private key file not found."""
    with pytest.raises(
        FileNotFoundError,
        match=r"Private key tests/assets/privatekey_file_doesnt_exist.key not found",
    ):
        Credentials(
            region=valid_region,
            cert_filename="tests/assets/client_rsa2048.pem",
            private_key_filename="tests/assets/privatekey_file_doesnt_exist.key",
            duration=3600,
            profile_arn=profile_arn,
            role_arn=role_arn,
            session_name="test_session",
            trust_anchor_arn=trust_anchor_arn,
        )


def test_session_duration() -> None:
    """Check upper and lower duration bounds."""
    durations = [300, 7200]

    for duration in durations:
        with pytest.raises(
            ValueError,
            match=r"Duration must be at least 15 minutes and less than 1 hour",
        ):
            Credentials(
                region=valid_region,
                cert_filename="tests/assets/client_rsa2048.pem",
                private_key_filename="tests/assets/client_rsa2048.key",
                duration=duration,
                profile_arn=profile_arn,
                role_arn=role_arn,
                session_name="test_session",
                trust_anchor_arn=trust_anchor_arn,
            )


# Call get_credentials and verify HTTP call and mocked AWS response
test_session = Credentials(
    region=valid_region,
    cert_filename="tests/assets/client_secp384r1.pem",
    private_key_filename="tests/assets/client_secp384r1.key",
    duration=3600,
    profile_arn=profile_arn,
    role_arn=role_arn,
    session_name="test_session",
    trust_anchor_arn=trust_anchor_arn,
)


def test_get_credentials_valid(requests_mock) -> None:
    """Use session fixture to exercise credential calls."""
    requests_mock.post(
        f"https://rolesanywhere.{valid_region}.amazonaws.com/sessions",
        status_code=200,
        json=valid_session_response,
    )
    response = test_session.get_credentials()
    assert response == valid_session_response
