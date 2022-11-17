from flask import Flask
from utils.cert import *
from utils.crypto import *

class CERT_SERVER():
    def __init__(self, host, port, CERT_FPATH, CERT_KEY_FPATH):
        self.host = host
        self.port = port
        self.cert_fpath = CERT_FPATH
        self.cert_key_fpath = CERT_KEY_FPATH
        self.app = Flask(__name__)

        @self.app.route("/")
        def hello():
            # return json.dumps({'success':True}), 200
            cert = load_cert_from_file_raw(self.cert_fpath)
            if cert is not None:
                return cert

    def run(self):
        context = (self.cert_fpath, self.cert_key_fpath)
        self.app.run(host=self.host, port=self.port, ssl_context=context)