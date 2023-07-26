import networkx as nx
from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.http import HTTPRequest

# Fonction pour traiter chaque paquet capturé
def process_packet(packet):
    # Vérifier si le paquet est IP
    if packet.haslayer(IP):
        # Obtenir les adresses source et destination
        src = packet[IP].src
        dst = packet[IP].dst

        # Obtenir le port et le service si le paquet est TCP ou UDP
        port = None
        service = None
        if packet.haslayer(TCP):
            port = packet[TCP].sport
            service = 'tcp'
        elif packet.haslayer(UDP):
            port = packet[UDP].sport
            service = 'udp'

        # Obtenir la version si le paquet est une requête HTTP
        version = None
        if packet.haslayer(HTTPRequest):
            version = packet[HTTPRequest].fields.get('User-Agent')

        # Ajouter les informations au graphe
        if G.has_edge(src, dst):
            G[src][dst]['packets'] += 1
            G[src][dst]['size'] += len(packet)
        else:
            G.add_edge(src, dst, packets=1, size=len(packet), port=port, service=service, version=version)

# Créer un graphe dirigé
G = nx.DiGraph()

# Capturer les paquets du réseau
sniff(iface='wlan0', prn=process_packet, count=100)

# Écrire le graphe au format dot
nx.nx_pydot.write_dot(G, 'attack.dot')

