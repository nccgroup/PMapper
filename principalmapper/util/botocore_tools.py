"""Utility functions for working with botocore"""

from typing import Optional

import botocore.session


def get_session(profile_arg: Optional[str]) -> botocore.session.Session:
    """Returns a botocore Session object taking into consideration Env-vars, etc.

    Tries to follow order from: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html
    """
    # command-line args (--profile)
    if profile_arg is not None:
        result = botocore.session.Session(profile=profile_arg)
    else:  # pull from environment vars
        result = botocore.session.get_session()

    stsclient = result.create_client('sts')
    stsclient.get_caller_identity()  # raises error if it's not workable
    return result
