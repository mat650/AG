import networkx as nx
import matplotlib.pyplot as plt

# Create a directed graph
G = nx.DiGraph()

# Add nodes and edges
G.add_edge("Initial infection (USB drive)", "Exploit Windows vulnerabilities")
G.add_edge("Exploit Windows vulnerabilities", "Establish presence")
G.add_edge("Establish presence", "Propagate over network")
G.add_edge("Propagate over network", "Identify target systems")
G.add_edge("Identify target systems", "Exploit Siemens Step7 software")
G.add_edge("Exploit Siemens Step7 software", "Alter PLC code")
G.add_edge("Alter PLC code", "Cause physical damage")
G.add_edge("Cause physical damage", "Send false feedback to operators")

# Draw the graph
nx.draw(G, with_labels=True, node_color='lightblue', font_weight='bold')
plt.show()

