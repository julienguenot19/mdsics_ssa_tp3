# -*- coding: utf-8 -*-
"""



"""

from flask import Flask

# définir le message secret
SECRET_MESSAGE = "parasaurolophus"
SSL_CONTEXT = "ssl/"
SSL_DOMAIN = "100.121.43.112"

app = Flask(__name__)

@app.route("/")
def get_secret_message():
    return SECRET_MESSAGE


if __name__ == "__main__":
    # HTTP version
    app.run(debug=True, host="0.0.0.0", port=8081, ssl_context=(SSL_CONTEXT + SSL_DOMAIN + ".pem", SSL_CONTEXT + SSL_DOMAIN + "-key.pem"))
    # HTTPS version
    # A compléter  : nécessité de déplacer les bons fichiers vers ce répertoire
   