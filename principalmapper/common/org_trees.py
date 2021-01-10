#  Copyright (c) NCC Group and Erik Steringer 2020. This file is part of Principal Mapper.
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

import json
import logging
import os
import os.path
from typing import List, Optional, Tuple

from principalmapper.common import Edge
from principalmapper.common.policies import Policy


logger = logging.getLogger(__name__)


class OrganizationAccount(object):
    """The OrganizationAccount object represents an account within an AWS Organization."""

    def __init__(self, account_id: str, scps: List[Policy], tags: Optional[dict]):
        self.account_id = account_id
        self.scps = scps
        if tags is None:
            self.tags = {}
        else:
            self.tags = tags

    def as_dictionary(self) -> dict:
        """Returns a dictionary representation of this OrganizationAccount object. Used for serialization to disk. We
        only return the SCP ARN since it is stored in a separate file."""

        return {
            'account_id': self.account_id,
            'scps': [x.arn for x in self.scps],
            'tags': self.tags
        }


class OrganizationNode(object):
    """The OrganizationNode object represents an Organizational Unit which can have its own Service Control Policy as
    well as a collection of AWS accounts."""

    def __init__(self, ou_id: str, ou_name: str, accounts: List[OrganizationAccount], child_nodes: list,
                 scps: List[Policy], tags: Optional[dict]):
        """
        Constructor. Note the self-referential typing.

        :type child_nodes List[OrganizationNode]
        """
        self.ou_id = ou_id
        self.ou_name = ou_name
        self.accounts = accounts
        self.child_nodes = child_nodes  # type: List[OrganizationNode]
        self.scps = scps
        if tags is None:
            self.tags = {}
        else:
            self.tags = tags

    def as_dictionary(self) -> dict:
        """Returns a dictionary representation of this OrganizationNode object. Used for serialization to disk. We
        only return the SCP ARN since it is stored in a separate file."""

        return {
            'ou_id': self.ou_id,
            'ou_name': self.ou_name,
            'accounts': [x.as_dictionary() for x in self.accounts],
            'child_nodes': [x.as_dictionary() for x in self.child_nodes],
            'scps': [x.arn for x in self.scps],
            'tags': self.tags
        }


class OrganizationTree(object):
    """The OrganizationGraph object represents an AWS Organization, which is a collection of AWS accounts. These
    accounts are organized in a hierarchy (we use a tree for this).
    """

    def __init__(self, org_id: str, management_account_id: str, root_ous: List[OrganizationNode],
                 all_scps: List[Policy], accounts: List[str], edge_list: List[Edge], metadata: dict):
        self.org_id = org_id
        self.management_account_id = management_account_id
        self.root_ous = root_ous
        self.all_scps = all_scps
        self.accounts = accounts
        self.edge_list = edge_list
        if 'pmapper_version' not in metadata:
            raise ValueError('The pmapper_version key/value (str) is required: {"pmapper_version": "..."}')
        self.metadata = metadata

    def as_dictionary(self) -> dict:
        """Returns a dictionary representation of this OrganizationTree object. Used for serialization to disk. We
        exclude the SCPs and metadata since `save_organization_to_disk` does those in a separate file."""

        return {
            'org_id': self.org_id,
            'management_account_id': self.management_account_id,
            'root_ous': [x.as_dictionary() for x in self.root_ous],
            'edge_list': [x.to_dictionary() for x in self.edge_list],
            'accounts': self.accounts
        }

    def save_organization_to_disk(self, dirpath: str):
        """Stores this Organization object as a collection of JSON data to disk, in a standard layout from the
        given root directory path.

        If the given path does not exist, we try to create it.

        Structure:
        | <root_directory parameter>
        |---- metadata.json
        |---- scps.json
        |---- org_data.json

        The client app (such as __main__.py of principalmapper) will specify where to retrieve the data."""

        rootpath = dirpath
        if not os.path.exists(rootpath):
            os.makedirs(rootpath, 0o700)

        metadata_filepath = os.path.join(rootpath, 'metadata.json')
        scps_filepath = os.path.join(rootpath, 'scps.json')
        org_data_filepath = os.path.join(rootpath, 'org_data.json')

        old_umask = os.umask(0o077)  # block rwx for group/all
        with open(metadata_filepath, 'w') as f:
            json.dump(self.metadata, f, indent=4)
        with open(scps_filepath, 'w') as f:
            json.dump([x.to_dictionary() for x in self.all_scps], f, indent=4)
        with open(org_data_filepath, 'w') as f:
            org_data_dict = self.as_dictionary()
            json.dump(org_data_dict, f, indent=4)
        os.umask(old_umask)

    @classmethod
    def create_from_dir(cls, dirpath: str):
        """This class method instantiates an OrganizationTree object with the contained
        OrganizationNode/OrganizationAccount objects."""

        # load up the Policy objects
        policies = {}
        policies_path = os.path.join(dirpath, 'scps.json')
        with open(policies_path) as fd:
            policies_list = json.load(fd)
        for policy_dict_obj in policies_list:
            policy_obj = Policy(policy_dict_obj['arn'], policy_dict_obj['name'], policy_dict_obj['policy_doc'])
            policies[policy_obj.arn] = policy_obj

        # load up the metadata object
        metadata_filepath = os.path.join(dirpath, 'metadata.json')
        with open(metadata_filepath) as fd:
            metadata_obj = json.load(fd)

        # load the OrganizationX objects
        org_datafile_path = os.path.join(dirpath, 'org_data.json')
        with open(org_datafile_path) as fd:
            org_dictrepr = json.load(fd)

        def _produce_ou(ou_dict: dict) -> OrganizationNode:
            return OrganizationNode(
                ou_dict['ou_id'],
                ou_dict['ou_name'],
                [OrganizationAccount(x['account_id'], [policies[y] for y in x['scps']], x['tags']) for x in ou_dict['accounts']],
                [_produce_ou(x) for x in ou_dict['child_nodes']],
                [policies[x] for x in ou_dict['scps']],
                ou_dict['tags']
            )

        # we have to build the OrganizationNodes first
        root_ous = [_produce_ou(x) for x in org_dictrepr['root_ous']]

        return OrganizationTree(
            org_dictrepr['org_id'],
            org_dictrepr['management_account_id'],
            root_ous,
            [x for x in policies.values()],
            org_dictrepr['accounts'],
            org_dictrepr['edge_list'],
            metadata_obj
        )
