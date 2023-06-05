#!/usr/bin/env python3

from scapy.all import sniff, IP
from scapy.layers.http import HTTPRequest
import sys
import time
from datetime import datetime
import json

if len(sys.argv) >= 3:
	print("Erreur d'utilisation du script")
	exit()

nb_sec = sys.argv[1]
ip_client = sys.argv[2]

Methode = []
Chemin = []
Version = []
Date = []
content = []

def check(p):
	if HTTPRequest in p and p[IP].src == ip_client:
		req = p[HTTPRequest]
		
		content.append(req.Method.decode("utf-8")) 
		content.append(req.Path.decode("utf-8"))
		content.append(req.Http_Version.decode("utf-8"))
		content.append(str(datetime.now()))
		if req.Method.decode("utf-8") == "POST":
			content.append(str(req.payload.load.decode("utf-8")))
	datae = {
		"methode":"",
		"chemin":"",
		"version":"",
		"date":"",
		"contenu":""
	}
	for data in content:
		datae.append({
		"methode":data[0],
		"chemin":data[1],
		"version":data[2],
		"date":data[3],
		"contenu":data[4]
	})	
	with open("Résultat.json", "w", encoding="utf-8") as filecontent:
            # Ajout des informations du dictionnaire data dans le fichier json
            json.dump(data, filecontent, indent=4)

sniff(prn=check, timeout=int(nb_sec))


