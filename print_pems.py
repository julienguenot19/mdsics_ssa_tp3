# -*- coding: utf-8 -*-
"""

Created on May 2022
@author: Mr ABBAS-TURKI

"""

import pem

def print_pems(filename: str):
    print(pem.parse_file(filename))