import socket
from scapy.layers.l2 import ARP
from scapy.layers.l2 import Ether
from scapy.layers.l2 import srp
#creation de la classe principale a appeler
class verifierPort():
# Scanner le réseau selon la plage d'adresse IP v4
    def check_port(ip_address, listPort):
        listPort = listPort
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for port in listPort:
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                print(f"Port {port} ouvert, Service --> " +socket.getservbyport(port))
            else:
                print(f"Port {port} fermé")
        sock.close()
#Scanner la liste des adresses IP v4 du réseau
    def map_network(plage):
        target_ip = plage
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=False)[0]

        ip_list = []
        for sent, received in result:
            ip_list.append(received.psrc)

        return ip_list
# connaittre les adresses Mac de chaque adresses IP v4 scannées du réseau
    def adresseMac(ip):
        target_ip = ip
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=False)[0]

        listeMac = []
        for sent, received in result:
            listeMac.append(received.hwsrc)

        return listeMac
#connaittre les services utilisé par les port de chque adresses IP v trouvées dans le réseau
    def serviceSurPort(port):
        try:
            service = socket.getservbyport(port)
            return service
        except OSError:
            return "Inconnu"
