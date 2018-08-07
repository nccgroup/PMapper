"""
A directed, unweighted graph for the purpose of tracking the relationships 
between different principals in an AWS account.

"""
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

from .awsedge import AWSEdge
from .awsnode import AWSNode

class AWSGraph:
    def __init__(self):
        self.nodes = []
        self.edges = []

    def __str__(self):
        return "AWS Graph with " + str(len(self.nodes)) + " nodes and " + str(len(self.edges)) + " edges"

    def __repr__(self):
        return str(self) # details aren't good to stash in memory when you've got 1.1M edges

    def write_to_fd(self, fd):
        """Write the graph file to the given file descriptor."""
        fd.write("[NODES]\n")
        for node in self.nodes:
            fd.write(repr(node))
            fd.write("\n")
        fd.write("[EDGES]\n")
        for edge in self.edges:
            fd.write("(")
            fd.write(str(self.nodes.index(edge.nodeX)))
            fd.write(",")
            fd.write(str(self.nodes.index(edge.nodeY)))
            fd.write(",'")
            fd.write(edge.shortlabel)
            fd.write("','")
            fd.write(edge.longlabel)
            fd.write("')\n")



