"""Test cases for the Credentials class."""
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from boto3.session import Session

from iamra import Credentials


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
                "expiration": (
                    datetime.now(timezone.utc) + timedelta(seconds=900)
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
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


def test_boto3_session_default(requests_mock) -> None:
    """Create boto3 session object."""
    requests_mock.post(
        f"https://rolesanywhere.{valid_region}.amazonaws.com/sessions",
        status_code=201,
        json=valid_session_response,
    )
    test_ec_session = Credentials(
        region=valid_region,
        certificate_filename="tests/assets/client_secp384r1.pem",
        private_key_filename="tests/assets/client_secp384r1.key",
        duration=3600,
        profile_arn=profile_arn,
        role_arn=role_arn,
        trust_anchor_arn=trust_anchor_arn,
    )
    # response = test_ec_session.get_credentials()
    # assert response == valid_session_response

    # Create boto3 session
    boto3_session = test_ec_session.get_boto3_session()
    assert isinstance(boto3_session, Session)
