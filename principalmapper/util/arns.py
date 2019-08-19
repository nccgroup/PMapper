"""Utility code for parsing and dealing with ARNs.

Documentation: https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html

All functions within assume a valid ARN is passed.

ARN Format:
arn:<partition>:<service>:<region>:<account id>:<resource/identifier>
"""


def get_partition(arn: str):
    """Returns the partition from a string ARN."""
    return arn.split(':')[1]


def get_service(arn: str):
    """Returns the service from a string ARN."""
    return arn.split(':')[2]


def get_region(arn: str):
    """Returns the region from a string ARN."""
    return arn.split(':')[3]


def get_account_id(arn: str):
    """Returns the account ID from a string ARN."""
    return arn.split(':')[4]


def get_resource(arn: str):
    """Returns the resource (trailing part) from a string ARN."""
    return ''.join(arn.split(':')[5:])


def validate_arn(arn: str) -> bool:
    """Returns true if the provided ARN appears to follow the expected structure of an ARN."""
    arn_arr = arn.split(':')
    if len(arn_arr) < 6:
        return False
    if arn_arr[0] != 'arn':
        return False
    return True
