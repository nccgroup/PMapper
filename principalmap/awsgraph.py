"""
A directed, unweighted graph for the purpose of tracking the relationships 
between different principals in an AWS account.

"""
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import threading
from .awsedge import AWSEdge
from .awsnode import AWSNode

class AWSGraph:
	def __init__(self):
		self.nodes = []
		self.edges = []
		self.lock = threading.Lock()

	def addedges(self, edgelist):
		with self.lock:
			self.edges.extend(edgelist)

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





