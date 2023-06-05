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

nb_sec = int(sys.argv[1])
ip_client = sys.argv[2]

content = []

def check(p):
    if HTTPRequest in p and p[IP].src == ip_client:
        req = p[HTTPRequest]
        
        content.append({
            "methode": req.Method.decode("utf-8"),
            "chemin": req.Path.decode("utf-8"),
            "version": req.Http_Version.decode("utf-8"),
            "date": str(datetime.now())
        })

        if req.Method.decode("utf-8") == "POST":
            content[-1]["contenu"] = req.payload.load.decode("utf-8")

    with open("Résultat.json", "w", encoding="utf-8") as filecontent:
        # Écriture du contenu dans le fichier JSON
        json.dump(content, filecontent, indent=4)

sniff(prn=check, timeout=nb_sec)
