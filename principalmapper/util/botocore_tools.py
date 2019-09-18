"""Utility functions for working with botocore"""

#  Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.
#
#      Principal Mapper is free software: you can redistribute it and/or modify
#      it under the terms of the GNU Affero General Public License as published by
#      the Free Software Foundation, either version 3 of the License, or
#      (at your option) any later version.
#
#      Principal Mapper is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU Affero General Public License for more details.
#
#      You should have received a copy of the GNU Affero General Public License
#      along with Principal Mapper.  If not, see <https://www.gnu.org/licenses/>.

from typing import Optional

import botocore.session


def get_session(profile_arg: Optional[str]) -> botocore.session.Session:
    """Returns a botocore Session object taking into consideration Env-vars, etc.

    Tries to follow order from: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html
    """
    # command-line args (--profile)
    if profile_arg is not None:
        result = botocore.session.Session(profile=profile_arg)
    else:  # pull from environment vars / metadata
        result = botocore.session.get_session()

    stsclient = result.create_client('sts')
    stsclient.get_caller_identity()  # raises error if it's not workable
    return result
