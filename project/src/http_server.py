from flask import Flask
from utils.debug import *

class HTTP_SERVER():
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.storage = {}
        self.app = Flask(__name__)

        @self.app.route('/.well-known/acme-challenge/<token>')
        def respond(token):
            return self.storage[token]
    
    def save_key_auth(self, token, value):
        self.storage[token] = value

    def run(self):    
        self.app.run(host=self.host, port=self.port)
