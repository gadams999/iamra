"""IAM Roles Anywhere Credentials object class and methods.

Creates an object that holds temporary AWS
credentials for a given IAM role using IAM Roles Anywhere.
"""

import base64
import datetime
import hashlib
import json
from pathlib import Path
from typing import Any
from typing import List
from typing import Optional
from typing import TypedDict
from typing import cast

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

from .exceptions import EncryptionAlgorithmError
from .exceptions import UntrustedCertificateError


class AssumedRoleUserType(TypedDict):
    """AssumedRoleUserType."""

    arn: str
    assumedRoleId: str  # noqa: N815


class CredentialsType(TypedDict):
    """CredentialsType."""

    accessKeyId: str  # noqa: N815
    expiration: float
    secretAccessKey: str  # noqa: N815
    sessionToken: str  # noqa: N815


class CredentialSet(TypedDict):
    """CredentialSet type."""

    assumedRoleUser: AssumedRoleUserType  # noqa: N815
    credentials: CredentialsType
    packedPolicySize: int  # noqa: N815
    roleArn: str  # noqa: N815
    sourceIdentity: str  # noqa: N815


class SessionResponse(TypedDict):
    """Returned Credentials dictionary format."""

    credentialSet: List[CredentialSet]  # noqa: N815
    subjectArn: str  # noqa: N815


class Credentials:
    """Creates credentials object for temporary AWS credentials.

    Attributes:
        None

    Returns:
        Credentials object

    Raises:
        FileNotFoundError: If certificate or private key files not found
        EncryptionAlgorithmError: Private key other than RSA or EC
    """

    def __init__(  # noqa: S107
        self,
        region: str,
        certificate_filename: str,
        private_key_filename: str,
        duration: int,
        profile_arn: str,
        role_arn: str,
        trust_anchor_arn: str,
        session_name: Optional[str] = None,
        passphrase: Optional[bytes] = None,
        certificate_chain_filename: Optional[str] = None,
    ):
        """Initialize object with session-specific details.

        Create and object ready to make a call to IAM Roles Anywhere for temporary
        credentials.

        Args:
            region: AWS Region
            certificate_filename: Path to the certificate file
            private_key_filename: Path to the private key file
            passphrase: Optional passphrase for the private key file
            certificate_chain_filename: File containing certificate chain to CA in trust anchor
            duration: Duration of the credentials in seconds
            profile_arn: ARN of the Roles Anywhere profile to use
            role_arn: Name of the IAM role attached to the profile arn to use
            session_name: Name of the Roles Anywhere session
            trust_anchor_arn: ARN of the Roles Anywhere trust anchor that signed the certificate

        Raises:
            ValueError: Invalid attribute values

        """
        # Set object variables from init
        self.region: str = region
        self.duration: int = duration
        self.profile_arn: str = profile_arn
        self.role_arn: str = role_arn
        self.session_name = session_name
        self.trust_anchor_arn: str = trust_anchor_arn
        self.credentials = {
            "accessKeyId": "",
            "expiration": "",
            "secretAccessKey": "",
            "sessionToken": "",
        }
        self.certificate_chain_der = certificate_chain_filename

        self.__set_pki_values(
            private_key_filename,
            certificate_filename,
            certificate_chain_filename,
            passphrase,
        )

        # Validate rest of initial values
        if self.duration < 900 or self.duration > 3600:
            raise ValueError(
                "Duration must be at least 15 minutes and less than 1 hour"
            )

    def get_credentials(self) -> Optional[SessionResponse]:  # noqa: C901
        """Generate temporary AWS credentials.

        Call IAM Roles Anywhere to vend credentials. Upon success
        set the credentials within the object and also return the
        full session response object.

        Args:
            None

        Raises:
            HTTPError: If general HTTP error in encountered
            ConnectionError: If unable to establish a connection to the endpoint
            Timeout: If response not received in time
            RequestException: General requests error
            UntrustedCertificateError: If certificate is not trusted or insufficient

        Returns:
            SessionResponse: Full response object from IAM Roles Anywhere

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
        # Add optional certificate chain header if provided
        if self.certificate_chain_der is not None:
            http_headers["X-Amz-X509-Chain"] = self.certificate_chain_der

        payload = {
            "durationSeconds": self.duration,
            "profileArn": self.profile_arn,
            "roleArn": self.role_arn,
            "trustAnchorArn": self.trust_anchor_arn,
        }
        # Add optional sessionName if provided
        if self.session_name is not None:
            payload["sessionName"] = self.session_name

        # Then dump to JSON string
        payload_str: str = json.dumps(payload)

        # Create canonical header entries (lowercase, trim, and sort)
        canonical_header_entries = []
        for entry in http_headers:
            canonical_header_entries.append(
                self.__canonical_header_entry(entry, http_headers[entry])
            )
        # Sort canonical headers by the header name (e.g., the x-amz-x509 in x-amz-x509:MII)
        canonical_header_entries = sorted(
            canonical_header_entries, key=lambda x: str(x.split(":")[0])
        )

        # Create the signed header list (e.g., content-type;host;x-amz-date;x-amz-x509)
        signed_headers = self.__signed_header_list(canonical_header_entries)

        # Craft the canonical request
        canonical_request: Any = (
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
            + hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
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
        signature = self.__sign_signature(string_to_sign, self.private_key)

        # Add Authorization header to request
        http_headers["Authorization"] = (
            f"{self.signing_method} Credential={self.certificate_serial_number}/{credential_scope}, "
            + f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        try:
            r = requests.post(
                f"https://rolesanywhere.{self.region}.amazonaws.com/sessions",
                headers=http_headers,
                data=payload_str.encode("utf-8"),
            )
        except requests.exceptions.HTTPError as errh:
            raise requests.exceptions.HTTPError(f"HTTP error: {errh}") from errh
        except requests.exceptions.ConnectionError as errc:
            raise requests.exceptions.ConnectionError(
                f"Error connecting: {errc}"
            ) from errc
        except requests.exceptions.Timeout as errt:
            raise requests.exceptions.Timeout(f"Timeout error: {errt}") from errt
        except requests.exceptions.RequestException as err:
            raise requests.exceptions.RequestException(f"Unknown error: {err}") from err

        # Completed response, determine if 200 (ok) or 4xx (error)
        if r.status_code != 201:
            if r.status_code == 403:
                raise UntrustedCertificateError(
                    f"Response status code {r.status_code}, response message: {r.text}"
                )
            else:  # pragma: no cover (will happen for all other 4XX codes)
                raise requests.exceptions.HTTPError(
                    f"Response status code {r.status_code}, response message: {r.text}"
                )

        # Set object credentials from response
        self.credentials = r.json()["credentialSet"][0]["credentials"]

        # Return complete response object
        return cast(SessionResponse, r.json())

    def __set_pki_values(  # noqa: C901
        self,
        private_key_filename: str,
        certificate_filename: str,
        certificate_chain_filename: Optional[str],
        passphrase: Optional[bytes],
    ) -> None:
        # Read the private key and certificate and set values for signing
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
            with open(Path(certificate_filename), "rb") as f:
                self.certificate = x509.load_pem_x509_certificate(
                    f.read(),
                )
                self.certificate_der: str = base64.b64encode(
                    self.certificate.public_bytes(serialization.Encoding.DER)
                ).decode("utf-8")
                self.certificate_serial_number = self.certificate.serial_number
        except FileNotFoundError as e:
            raise FileNotFoundError(
                f"Certificate {certificate_filename} not found"
            ) from e

        # If the certificate is signed by a CA underneath one in the trust anchor
        # the contents of the certificate chain is read and header used during signing
        if certificate_chain_filename:
            try:
                with open(Path(certificate_chain_filename), "rb") as f:
                    certificate_chain = x509.load_pem_x509_certificates(f.read())
                certificates_in_der: List[str] = []
                for cert in certificate_chain:
                    certificates_in_der.append(
                        base64.b64encode(
                            cert.public_bytes(serialization.Encoding.DER)
                        ).decode("utf-8")
                    )
                self.certificate_chain_der = ",".join(certificates_in_der)
            except FileNotFoundError as e:
                raise FileNotFoundError(
                    f"Certificate chain {certificate_chain_filename} not found"
                ) from e

    @staticmethod
    def __canonical_header_entry(name: str, value: str) -> str:
        return f"{name.lower()}:{' '.join(value.split())}"

    @staticmethod
    def __signed_header_list(headers: list) -> str:
        entry = ""
        for header in headers:
            entry += header.split(":")[0] + ";"
        # trim final ; then create has
        return entry[:-1]

    @staticmethod
    def __sign_signature(string_to_sign: str, key) -> str:
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
        else:  # pragma: no cover
            raise TypeError("Unsupported key type")
        return signature.hex()
