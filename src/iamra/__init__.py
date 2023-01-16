"""IAM Roles Anywhere credentials helper.

Iamra (ahy-em-rah) is a helper library to abstract and make obtaining
temporary AWS IAM credentials easy. See the documentation at:
https://pypi.org/project/iamra

Basic usage with local private key and X.509 certificate:

   >>> import iamra
   >>> session = iamra.Credentials(
           region="us-east-1",
           certificate_filename="client.pem",
           private_key_filename="client.key",
           duration=3600,
           profile_arn="arn:aws:rolesanywhere:us-west-2:1234567890:profile/3d203fc0-7bba-4ec1-a6ef-697504ce1c72",
           role_arn="arn:aws:iam::1234567890:role/IamRoleWithPermissionsToUse",
           session_name="my_client_test_session",
           trust_anchor_arn="arn:aws:rolesanywhere:us-west-2:1234567890:trust-anchor/29efd0b1-1b66-4df4-8ae7-e935716efd8e",
    )
    >>> session.get_credentials()
    >>> session.access_key_id
    'ASIA5FLYQEXXXXXXZ27N'
    >>> session.secret_access_key
    'HhAViXXXXqIZrq/qENC4ahPqssXXXX9DEfx3mTv'
    >>> session.session_token
    'IQoJb3JpZ2luX2VjEMf//////////wEaCXVzLXdlc3QtMiJHMEUCIEz9JVF+nQce3rmd6OmfJAbTHNbG7RJLEEa6xECqEEbQAiEA6yd2mbe0akoO+np/EgrSA/
    ...
    fARzrFrr0VEpiqFY42NWjFdFUhdLkPiuhsLoTYH+OnaGl92OxAho3j0='

:copyright: (c) Gavin Adams
:license: Apache License, Version 2.0, see LICENSE for more details.
"""

# import classes to make available without second level import
from .session import Credentials


__all__ = ["Credentials"]
