# -*- coding: utf-8 -*-
"""
Created on May 2022
@author: Mr ABBAS-TURKI
"""

import pem
import sys
import os

def print_pems(filename: str):
    """
    Affiche le contenu brut des objets PEM (Certificats, Clés, CSR) contenus dans un fichier.
    """
    print(f"\n{'='*20} Visualisation de : {os.path.basename(filename)} {'='*20}")
    
    try:
        # La librairie 'pem' parse le fichier et trouve tous les blocs PEM
        pem_objects = pem.parse_file(filename)
        
        if not pem_objects:
            print(f"[INFO] Aucun bloc PEM valide trouvé dans {filename}.")
            return

        # On itère sur chaque objet trouvé (il peut y en avoir plusieurs, ex: chaîne de certifs)
        for i, obj in enumerate(pem_objects, 1):
            #print(f"--- Bloc {i} ({obj.__class__.__name__}) ---")
            # Affiche le contenu textuel du PEM (-----BEGIN ... END-----)
            print(str(obj))
            
    except FileNotFoundError:
        print(f"[ERREUR] Le fichier '{filename}' est introuvable.")
    except Exception as e:
        print(f"[ERREUR] Impossible de lire '{filename}' : {e}")

if __name__ == "__main__":
    # Permet de tester le script en ligne de commande : python print_pems.py mon_fichier.pem
    if len(sys.argv) > 1:
        print_pems(sys.argv[1])
    else:
        print("Usage: python print_pems.py <fichier.pem>")