"""Code to coordinate identifying edges between principals in an AWS account"""

import io
import os
from typing import List

import botocore.session

from principalmapper.common.edges import Edge
from principalmapper.common.nodes import Node
from principalmapper.graphing.iam_edges import IAMEdgeChecker
from principalmapper.graphing.sts_edges import STSEdgeChecker
from principalmapper.util.debug_print import dprint


# Externally referable dictionary with all the supported edge-checking types
checker_map = {
    'iam': IAMEdgeChecker,
    'sts': STSEdgeChecker
}


def obtain_edges(session: botocore.session.Session, checker_list: List[str], nodes: List[Node],
                 output: io.StringIO = os.devnull, debug: bool = False) -> List[Edge]:
    """Given a list of nodes and a botocore Session, return a list of edges between those nodes. Only checks
    against services passed in the checker_list param."""
    result = []
    output.write('Initiating edge checks.\n')
    dprint(debug, 'Checker map:  {}'.format(checker_map))
    dprint(debug, 'Checker list: {}'.format(checker_list))
    for check in checker_list:
        if check in checker_map:
            output.write('running edge check for service: {}\n'.format(check))
            checker_obj = checker_map[check](session)
            result.extend(checker_obj.return_edges(nodes, output, debug))
    return result
