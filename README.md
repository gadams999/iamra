<!-- cSpell:ignore Codecov, FLYQEXXXXXXZ, Pqss, Xdlc, cjolowicz
}] -->

# Iamra

[![PyPI](https://img.shields.io/pypi/v/iamra.svg)][pypi_]
[![Status](https://img.shields.io/pypi/status/iamra.svg)][status]
[![Python Version](https://img.shields.io/pypi/pyversions/iamra)][python version]
[![License](https://img.shields.io/pypi/l/iamra)][license]

[![Read the documentation at https://iamra.readthedocs.io/](https://img.shields.io/readthedocs/iamra/latest.svg?label=Read%20the%20Docs)][read the docs]
[![Tests](https://github.com/gadams999/iamra/workflows/Tests/badge.svg)][tests]
[![Codecov](https://codecov.io/gh/gadams999/iamra/branch/main/graph/badge.svg)][codecov]

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)][pre-commit]
[![Black](https://img.shields.io/badge/code%20style-black-000000.svg)][black]

[pypi_]: https://pypi.org/project/iamra/
[status]: https://pypi.org/project/iamra/
[python version]: https://pypi.org/project/iamra
[read the docs]: https://iamra.readthedocs.io/
[tests]: https://github.com/gadams999/iamra/actions?workflow=Tests
[codecov]: https://app.codecov.io/gh/gadams999/iamra
[pre-commit]: https://github.com/pre-commit/pre-commit
[black]: https://github.com/psf/black

IAM Roles Anywhere credentials helper.

Iamra (ahy-em-rah) is a helper library to abstract and make obtaining temporary AWS IAM credentials easy through using [AWS Identity and Access Management Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html). Once configured in the cloud, Iamra sessions can be created, and then when credentials are needed, a single call will update the AWS credentials, that can be directly used via [boto3 session or client](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html).

## Features

- Single object per session, allowing for different scoped credentials
- RSA and EC certificate / private key support
- Certificate chain support for X.509 certificated signed by an intermediate Certificate Authority
- Cached credentials within the expiration time to reduce unneeded calls to IAM Roles Anywhere, but can be force-refreshed as needed

## Requirements

- Python 3.9 or later support
- Creation of a trust anchor and profile [in the cloud](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html)
- Valid X.509 certificate, private key, and optionally a certificate chain file

## Installation

You can install _Iamra_ via [pip] from [PyPI]:

<!-- markdownlint-disable -->

```console
$ pip install iamra
```

<!-- markdownlint-restore -->

## Usage

Basic usage with local private key and X.509 certificate:

```python
>>> import iamra
>>> # Create a session object
>>> iamra_session = iamra.Credentials(
       region="us-east-1",
       certificate_filename="client.pem",
       private_key_filename="client.key",
       duration=3600,
       profile_arn="arn:aws:rolesanywhere:us-west-2:1234567890:profile/3d203fc0-7bba-4ec1-a6ef-697504ce1c72",
       role_arn="arn:aws:iam::1234567890:role/IamRoleWithPermissionsToUse",
       session_name="my_client_test_session",
       trust_anchor_arn="arn:aws:rolesanywhere:us-west-2:1234567890:trust-anchor/29efd0b1-1b66-4df4-8ae7-e935716efd8e",
)
>>> # Invoke getting credentials from Roles Anywhere
>>> iamra_session.get_credentials()
>>> # Directly access credentials
>>> iamra_session.access_key_id
'ASIA5FLYQEXXXXXXZ27N'
>>> iamra_session.secret_access_key
'HhAViXXXXqIZrq/qENC4ahPqssXXXX9DEfx3mTv'
>>> iamra_session.session_token
'IQoJb3JpZ2luX2VjEMf//////////wEaCXVzLXdlc3QtMiJ...fARzrFrr0VEpiqFY42NWjFdFUhdLkPiuhsLoTYH+OnaGl92OxAho3j0='
```

## Documentation

[Here](https://iamra.readthedocs.io/en/latest/) is the documentation that covers advanced usage and module reference.

## Contributing

Contributions are very welcome.
To learn more, see the [Contributor Guide].

## License

Distributed under the terms of the [MIT license][license],
_Iamra_ is free and open source software.

## Issues

If you encounter any problems,
please [file an issue] along with a detailed description.

## Credits

This project was generated from [@cjolowicz]'s [Hypermodern Python Cookiecutter] template.

[@cjolowicz]: https://github.com/cjolowicz
[pypi]: https://pypi.org/
[hypermodern python cookiecutter]: https://github.com/cjolowicz/cookiecutter-hypermodern-python
[file an issue]: https://github.com/gadams999/iamra/issues
[pip]: https://pip.pypa.io/

<!-- github-only -->

[license]: https://github.com/gadams999/iamra/blob/main/LICENSE
[contributor guide]: https://github.com/gadams999/iamra/blob/main/CONTRIBUTING.md
