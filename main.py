# J'importe la classe de mon fichier check_port.py en tant qu'un alias VP
from check_port import verifierPort as VP
# je définis la plage d'adresses IP a Scanner
plage = "192.168.1.1/24"
# Je définis la liste des port a scanner sur chaque adresses ip trouvées dans le réseau
listPort = (80,443,21,22,23,3306)
# On exécute le tout
if __name__ == "__main__":
    print("Mappage du réseau... en cours")
    ip_addresses = VP.map_network(plage)
    for ip in ip_addresses:
        print("Recherche pour ---> " + ip + ", MAC ---> "+ str(VP.adresseMac(ip)))
        resultat = VP.check_port(ip, listPort)
        print(resultat)
