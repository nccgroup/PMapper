"""Code for creating graphs for Principal Mapper"""

from principalmapper.common.graphs import Graph


def create_new_graph():
    """Implements creating a graph from AWS API data and returning the resulting Graph object"""
    pass


def get_graph_from_disk(account):
    """Returns a Graph object constructed from data stored on-disk"""
    return Graph.create_graph_from_local_disk(account_id=account)


def get_existing_graph(parsed_args):
    """Implements creating a graph from data stored on disk and returning the resulting Graph object"""
    if parsed_args.account is not None:
        graph = get_graph_from_disk(parsed_args.account)
    else:
        raise NotImplementedError('Need to grab account ID via botocore session object.')

    print()

