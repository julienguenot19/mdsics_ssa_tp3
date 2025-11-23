# -*- coding: utf-8 -*-
"""



"""

from tools.core import Configuration
from ca.core import CertificateAuthority
from server.core import Server
from print_pems import print_pems

RESOURCES_DIR = "resources/"
CA_PRIVATE_KEY_FILENAME = RESOURCES_DIR + "ca-private-key.pem"
CA_PUBLIC_KEY_FILENAME = RESOURCES_DIR + "ca-public-key.pem"
SERVER_PRIVATE_KEY_FILENAME = RESOURCES_DIR + "server-private-key.pem"
SERVER_CSR_FILENAME = RESOURCES_DIR + "server-csr.pem"
SERVER_PUBLIC_KEY_FILENAME = RESOURCES_DIR + "server-public-key.pem"
CA_PASSWORD = "bla123"
SERVER_PASSWORD = "bla987"

CA_CONFIGURATION = Configuration("FR", "Territoire de Belfort", "Sevenans", "UTBM_CA", "localhost") 
SERVER_CONFIGURATION = Configuration("FR", "Territoire de Belfort", "Sevenans", "UTBM_SER", "localhost")

# Création de l'autorité de certification
certificate_authority = CertificateAuthority(CA_CONFIGURATION, CA_PASSWORD, CA_PRIVATE_KEY_FILENAME, CA_PUBLIC_KEY_FILENAME) 
    # regardez en haut et ca/core.py

# Création du server
server =Server(SERVER_CONFIGURATION, SERVER_PASSWORD, SERVER_PRIVATE_KEY_FILENAME, SERVER_CSR_FILENAME) 
    # regardez en haut et server/core.py

# Signature du certificat par l'autorité de certification
signed_certificate = certificate_authority.sign(server.get_csr(), SERVER_PUBLIC_KEY_FILENAME)

print_pems(CA_PUBLIC_KEY_FILENAME)
print_pems(SERVER_PRIVATE_KEY_FILENAME)
print_pems(SERVER_CSR_FILENAME)
print_pems(SERVER_PUBLIC_KEY_FILENAME)

print("Done")