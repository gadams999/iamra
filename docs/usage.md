# Usage

`iamra` is used with a X.509 certificate and corresponding private key to obtain temporary AWS credentials. See the [Basic Usage](reference) example to get started.

An _Iamra_ session is created by providing a Roles Anywhere trusted X.509 certificate and private key in PEM format, along with the specific Roles Anywhere _trust anchor_, _IAM role_, and the Roles Anywhere _profile_ that scopes down permissions of the _IAM role_.

```python
import iamra

session = iamra.Credentials(
    region="us-west-2",
    certificate_filename="client.crt.pem",
    private_key_filename="client.key.pem",
    certificate_chain_filename="ca_chain_bundle.pem",
    duration=3600,
    profile_arn="arn:aws:rolesanywhere:us-west-2:1234567890:profile/3d203fc0-7bba-4ec1-a6ef-697504ce1c72",
    role_arn="arn:aws:iam::1234567890:role/RolesAnywhereTestRole",
    session_name="my_client_session",
    trust_anchor_arn="arn:aws:rolesanywhere:us-west-2:1234567890:trust-anchor/29efd0b1-1b66-4df4-8ae7-e935716efd8e",
)
```

Once created, there are two methods that can be called, `get_credentials()` or `get_boto3_session()`. If a temporary set of credentials is needed for a single AWS call, or an SDK other than boto3 is being used, calling `get_credentials()` will populate the session attributes with AWS credentials.

```python
session.get_credentials()
print(session.access_key_id)
ASIA5FLYQEXXXXXXZ27N
print(session.secret_access_key)
HhAViXXXXqIZrq/qENC4ahPqssXXXX9DEfx3mTv
print(session.session_token)
IQoJb3JpZ2luX2VjEMf//////////wEaCXVzLXdlc3QtMiJ...fARzrFrr0VEpiqFY42NWjFdFUhdLkPiuhsLoTYH+OnaGl92OxAho3j0=
```

However, it is expected most will use this in conjunction with boto3. Calling `get_boto3_session()` will return a boto3 [session](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html) (or service client interface). This can then be used to create boto3 clients to make AWS service calls. Also, the returned session object will refresh its' credentials as they get near, or go beyond, the expiration time, without any other operations required.

```python
import boto3

boto3_session = session.get_boto3_session()
iot_client = boto3_session.client("iot")
print(iot_client.describe_thing(thingName="my_iot_device"))
{'ResponseMetadata': {'RequestId': 'ac77ac49-0dae-xxxx-afe1-84a50d57bf4d',
  'HTTPStatusCode': 200,
  'HTTPHeaders': {'date': 'Wed, 18 Jan 2023 21:17:01 GMT',
   'content-type': 'application/json',
   'content-length': '229',
   'connection': 'keep-alive',
   'x-amzn-requestid': 'ac77ac49-0dae-xxxx-afe1-84a50d57bf4d'},
  'RetryAttempts': 0},
 'defaultClientId': 'my_iot_device',
 'thingName': 'my_iot_device',
 'thingId': '6cac460d-2612-xxxx-b8ff-b75818c0b788',
 'thingArn': 'arn:aws:iot:us-west-2:1234567890:thing/my_iot_device',
 'attributes': {},
 'version': 1}
```

**Note:** Only create a single boto3 session from an Iamra object. If different credentials or region are required, create additional Iamra sessions for each corresponding boto3 session. For example, the two sessions below are created from `us-east-1` Roles Anywhere configuration, but the second European session for AWS service calls specifies the region to use when making those calls via boto3.

```python
import iamra

# region: us-east-1
us_session = iamra.Credentials(...)
boto3_session_us = us_session.get_boto3_session()

# Credentials still using us-east-1 for Roles Anywhere
europe_session = iamra.Credentials(...)
boto3_session_europe = europe_session.get_boto3_session(region="eu-central-1")
```

Please open an issue if there are other features you would like added to the module!
