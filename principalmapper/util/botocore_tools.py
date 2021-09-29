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

import logging
from typing import List, Optional

import botocore.session


logger = logging.getLogger(__name__)


def get_session(profile_arg: Optional[str], stsargs: Optional[dict] = None) -> botocore.session.Session:
    """Returns a botocore Session object taking into consideration Env-vars, etc.

    Tries to follow order from: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html
    """
    # command-line args (--profile)
    if profile_arg is not None:
        result = botocore.session.Session(profile=profile_arg)
    else:  # pull from environment vars / metadata
        result = botocore.session.get_session()

    # handles args for creating the STS client
    if stsargs is None:
        processed_stsargs = {}
    else:
        processed_stsargs = stsargs

    stsclient = result.create_client('sts', **processed_stsargs)
    stsclient.get_caller_identity()  # raises error if it's not workable
    return result


def get_regions_to_search(session: botocore.session.Session, service_name: str, region_allow_list: Optional[List[str]] = None, region_deny_list: Optional[List[str]] = None) -> List[str]:
    """Using a botocore Session object, the name of a service, and either an allow-list or a deny-list (but not both),
    return a list of regions to be used during the gathering process. This uses the botocore Session object's
    get_available_regions method as the base list.

    If the allow-list is specified, the returned list is the union of the base list and the allow-list. No error is
    thrown if a region is specified in the allow-list but not included in the base list.

    If the deny-list is specified, the returned list is the base list minus the elements of the deny-list. No error is
    thrown if a region is specified inthe deny-list but not included in the base list.

    A ValueError is thrown if the allow-list AND deny-list are both not None.
    """

    if region_allow_list is not None and region_deny_list is not None:
        raise ValueError('This function allows only either the allow-list or the deny-list, but NOT both.')

    base_list = session.get_available_regions(service_name)

    result = []

    if region_allow_list is not None:
        for element in base_list:
            if element in region_allow_list:
                result.append(element)
    elif region_deny_list is not None:
        for element in base_list:
            if element not in region_deny_list:
                result.append(element)
    else:
        result = base_list

    logger.debug('Final list of regions for {}: {}'.format(service_name, result))

    return result
