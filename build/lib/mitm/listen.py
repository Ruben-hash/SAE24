#!/usr/bin/env python3

from scapy.all import sniff, IP
from scapy.layers.http import HTTPRequest
import sys
import time
from datetime import datetime
import json

if len(sys.argv) != 3:
	print("Erreur d'utilisation du script")
	exit()

nb_sec = sys.argv[1]
ip_client = sys.argv[2]

resultat = []
corps = []

def check(p):
	if HTTPRequest in p and p[IP].src == ip_client:
		req = p[HTTPRequest]
		dico1 = {
			"Methode": req.Method.decode("utf-8"),
			"Chemin": req.Path.decode("utf-8"),
			"Version": req.Http_Version.decode("utf-8"),
			"Date": str(datetime.now())
		}
		resultat.append(dico1)
		if req.Method.decode("utf-8") == "POST":
			dico2 = {
				"Contenu": str(req.payload.load.decode("utf-8")),
			}
			corps.append(dico2)
			

sniff(prn=check, timeout=int(nb_sec))

print(resultat)
print(corps)
f = open("Résultat.json", "a")
f.write(json.dumps(resultat))
f.write(json.dumps(corps))
f.close()

