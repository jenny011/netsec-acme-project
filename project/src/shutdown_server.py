from flask import Flask, request
import json

class SHUTDOWN_SERVER():
    def __init__(self, host, port, q):
        self.host = host
        self.port = port
        self.q = q

        self.app = Flask(__name__)
        @self.app.route("/shutdown")
        def shutdown():
            self.q.put(True)
            return json.dumps({'success':True}), 200

    def run(self):
        self.app.run(host=self.host, port=self.port)