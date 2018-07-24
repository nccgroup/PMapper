"""
A directed, unweighted graph for the purpose of tracking the relationships 
between different principals in an AWS account.

"""
from __future__ import absolute_import, print_function, unicode_literals

from .awsedge import AWSEdge
from .awsnode import AWSNode


class AWSGraph:
	def __init__(self):
		self.nodes = []
		self.edges = []

	def __str__(self):
		return "AWS Graph with " + str(len(self.nodes)) + " nodes and " + str(len(self.edges)) + " edges"

	def __repr__(self):
		result = "[NODES]\n"
		for node in self.nodes:
			result += repr(node) + "\n"
		result += "[EDGES]\n"
		for edge in self.edges:
			result += "(" + str(self.nodes.index(edge.nodeX)) + "," + str(self.nodes.index(edge.nodeY)) + ",'" + edge.shortlabel + "','" + edge.longlabel + "')\n"
		return result
