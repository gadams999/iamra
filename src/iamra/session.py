"""IAM Roles Anywhere Credentials object class and methods.

Creates an object that holds temporary AWS
credentials for a given IAM role using IAM Roles Anywhere.
"""

import base64
import datetime
import hashlib
import json
from pathlib import Path
from typing import List
from typing import Optional
from typing import TypedDict

import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


class AssumedRoleUserType(TypedDict):
    """AssumedRoleUserType."""

    arn: str
    assumed_role_id: str


class CredentialsType(TypedDict):
    """CredentialsType."""

    access_key_id: str
    expiration: float
    secret_access_key: str
    session_token: str


class CredentialSet(TypedDict):
    """CredentialSet type."""

    assumed_role_user: AssumedRoleUserType
    credentials: CredentialsType
    packed_policy_size: int
    role_arn: str
    source_identity: str


class SessionResponse(TypedDict):
    """Returned Credentials dictionary format."""

    credential_set: List[CredentialsType]
    subject_arn: str


class EncryptionAlgorithmError(Exception):
    """Define error class."""

    pass


class Credentials:
    """Creates credentials object for temporary AWS credentials.

    Attributes:
        None

    Returns:
        Credentials object
    """

    def __init__(  # noqa: S107
        self,
        region: str,
        cert_filename: str,
        private_key_filename: str,
        duration: int,
        profile_arn: str,
        role_arn: str,
        session_name: str,
        trust_anchor_arn: str,
        passphrase: Optional[bytes] = None,
    ):
        """Initialize object with session-specific details.

        Create and object ready to make a call to IAM Roles Anywhere for temporary
        credentials.

        Args:
            region: AWS Region
            cert_filename: Path to the certificate file
            private_key_filename: Path to the private key file
            duration: Duration of the credentials in seconds
            profile_arn: ARN of the Roles Anywhere profile to use
            role_arn: Name of the IAM role attached to the profile arn to use
            session_name: Name of the Roles Anywhere session
            trust_anchor_arn: ARN of the Roles Anywhere trust anchor that signed the certificate
            passphrase: Optional passphrase for the private key file

        Raises:
            FileNotFoundError: If certificate or private key files not found
            ValueError: Invalid attribute values
            EncryptionAlgorithmError: Private key other than RSA or EC

        """
        # Set object variables from init
        self.region: str = region
        self.duration = duration
        self.profile_arn = profile_arn
        self.role_arn = role_arn
        self.session_name = session_name
        self.trust_anchor_arn = trust_anchor_arn
        self.credentials = {
            "accessKeyId": "",
            "expiration": "",
            "secretAccessKey": "",
            "sessionToken": "",
        }

        # Read the private key and certificate
        try:
            with open(Path(private_key_filename), "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=passphrase
                )
                if isinstance(self.private_key, rsa.RSAPrivateKey):
                    self.signing_method = "AWS4-X509-RSA-SHA256"
                elif isinstance(self.private_key, ec.EllipticCurvePrivateKey):
                    self.signing_method = "AWS4-X509-ECDSA-SHA256"
                else:
                    raise EncryptionAlgorithmError(
                        "Unknown private key type, only RSA and EC keys "
                        + "are supported for IAM Roles Anywhere"
                    )
        except ValueError as e:
            raise ValueError(e) from e
        except FileNotFoundError as e:
            raise FileNotFoundError(
                f"Private key {private_key_filename} not found"
            ) from e

        try:
            with open(Path(cert_filename), "rb") as f:
                self.certificate = x509.load_pem_x509_certificate(
                    f.read(),
                )
                self.certificate_der: str = base64.b64encode(
                    self.certificate.public_bytes(serialization.Encoding.DER)
                ).decode("utf-8")
                self.certificate_serial_number = self.certificate.serial_number
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Certificate {cert_filename} not found") from e

        # Validate rest of initial values
        if self.duration < 900 or self.duration > 3600:
            raise ValueError(
                "Duration must be at least 15 minutes and less than 1 hour"
            )

    def get_credentials(self) -> SessionResponse:
        """Generate temporary AWS credentials.

        Call IAM Roles Anywhere to vend credentials. Upon success
        set the credentials within the object and also return the
        full session response object.

        Args:
            None

        Raises:
            urllib3.exceptions.HTTPError:
            For all HTTP call and AWS responses, until we have more tests.

        Returns:
            CredentialSet
        """
        # Build request
        # generate time and date for use in signing the request
        dt = datetime.datetime.utcnow()
        request_date_time = dt.strftime("%Y%m%dT%H%M%SZ")
        request_date = dt.strftime("%Y%m%d")

        # define headers and payload to sign and send
        http_headers = {
            "Host": f"rolesanywhere.{self.region}.amazonaws.com",
            "Content-Type": "application/json",
            "X-Amz-Date": request_date_time,
            "X-Amz-X509": self.certificate_der,
        }
        payload = {
            "durationSeconds": self.duration,
            "profileArn": self.profile_arn,
            "roleArn": self.role_arn,
            "trustAnchorArn": self.trust_anchor_arn,
        }
        # add sessionName if provided
        if self.session_name is not None:
            payload["sessionName"] = self.session_name
        # Then dump to JSON string
        payload = json.dumps(payload)

        # Create canonical header entries (lowercase, trim, and sort)
        canonical_header_entries = []
        for entry in http_headers:
            canonical_header_entries.append(
                self._canonical_header_entry(entry, http_headers[entry])
            )
        canonical_header_entries.sort()

        # Create the signed header list (e.g., content-type;host;x-amz-date;x-amz-x509)
        signed_headers = self._signed_header_list(canonical_header_entries)

        # Craft the canonical request
        canonical_request = (
            "POST"
            + "\n"
            + "/sessions"
            + "\n"
            + ""  # canonical query string
            + "\n"
            + "".join(f"{entry}\n" for entry in canonical_header_entries)
            + "\n"
            + signed_headers
            + "\n"
            + hashlib.sha256(payload.encode("utf-8")).hexdigest()
        )

        # Hash the canonical request
        canonical_request_hash = hashlib.sha256(
            canonical_request.encode("utf-8")
        ).hexdigest()

        credential_scope = f"{request_date}/{self.region}/rolesanywhere/aws4_request"

        # Craft string to sign
        string_to_sign = (
            self.signing_method
            + "\n"
            + request_date_time
            + "\n"
            + credential_scope
            + "\n"
            + canonical_request_hash
        )

        # Complete by creating signature for use in HTTP Authorization header
        signature = self._sign_signature(string_to_sign, self.private_key)

        # Call Roles Anywhere
        http = urllib3.PoolManager()

        # Add Authorization header to request
        http_headers["Authorization"] = (
            f"{self.signing_method} Credential={self.certificate_serial_number}/{credential_scope}, "
            + f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        try:
            r = http.request(
                "POST",
                f"https://rolesanywhere.{self.region}.amazonaws.com/sessions",
                headers=http_headers,
                body=payload.encode("utf-8"),
            )
        except urllib3.exceptions.HTTPError as e:
            # Raise all urllib3 exceptions
            print(r.headers)
            raise urllib3.exceptions.HTTPError(f"HTTP error: {e}") from e

        # Completed response, determine if 200 (ok) or 4xx (error)

        # Set object credentials from response
        print(f"{r.status}\n{r.headers}")
        self.credentials = r.data["credentialSet"][0]["credentials"]

        return SessionResponse(r.data)

    @staticmethod
    def _canonical_header_entry(name: str, value: str) -> str:
        return f"{name.lower()}:{' '.join(value.split())}"

    @staticmethod
    def _signed_header_list(headers: list) -> str:
        entry = ""
        for header in headers:
            entry += header.split(":")[0] + ";"
        # trim final ; then create has
        return entry[:-1]

    @staticmethod
    def _sign_signature(string_to_sign: str, key) -> str:
        """Signs a string with the private key."""
        if isinstance(key, rsa.RSAPrivateKey):
            signature = key.sign(
                data=string_to_sign.encode("utf-8"),
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                algorithm=hashes.SHA256(),
            )
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            signature = key.sign(
                string_to_sign.encode("utf-8"), ec.ECDSA(hashes.SHA256())
            )
        return signature.hex()
