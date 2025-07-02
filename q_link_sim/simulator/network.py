import networkx as nx
import random
import numpy as np

def create_quantum_network(num_nodes: int = 5, connectivity_prob: float = 0.4) -> nx.Graph:
  """
  Creates a random quantum network (Erdos-Renyi graph).

  Args:
      num_nodes (int): The number of nodes in the network.
      connectivity_prob (float): The probability of an edge existing between any two nodes.

  Returns:
      nx.Graph: A NetworkX graph representing the quantum network.
  """
  graph = nx.erdos_renyi_graph(num_nodes, connectivity_prob, seed=42)
  # Ensure all nodes are connected, if not, add edges to make it connected
  while not nx.is_connected(graph):
      # Find two disconnected components and add an edge between them
      components = list(nx.connected_components(graph))
      u = random.choice(list(components[0]))
      v = random.choice(list(components[1]))
      graph.add_edge(u, v)
  
  # Assign names to nodes (e.g., Node 0, Node 1, ...)
  mapping = {i: f"Node {i}" for i in range(num_nodes)}
  graph = nx.relabel_nodes(graph, mapping)
  
  return graph

def get_node_positions(graph: nx.Graph) -> dict:
  """
  Generates positions for nodes in the graph for visualization.

  Args:
      graph (nx.Graph): The network graph.

  Returns:
      dict: A dictionary of node positions.
  """
  # Use a spring layout for better visual distribution
  return nx.spring_layout(graph, seed=42, k=0.8, iterations=50)
