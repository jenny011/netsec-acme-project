# get account post
    # jwk = get_jwk_rsa(self._public_key, self._alg)
    # protected_hdr = {"alg": self._alg, "jwk": jwk, "nonce": self._nonce, "url": self._subdir_url["newAccount"]}
    # payload = {"termsOfServiceAgreed": True}
    # jws_body = get_jws(self._private_key, protected_hdr, payload)
    # r = requests.post(self._subdir_url["newAccount"], headers=self._jose_hdr, data=jws_body, verify="./pebble.minica.pem")

# submit order post
    # protected_hdr = {"alg": self._alg, "kid": self._account_url, "nonce": self._nonce, "url": self._subdir_url["newOrder"]}
    # identifiers = []
    # for domain in domains:
    #     if domain[0] == "*":
    #         domain = domain.lstrip("*.")
    #     identifiers.append({"type":"dns", "value":domain})
    # payload = {"identifiers":identifiers}
    # jws_body = get_jws(self._private_key, protected_hdr, payload)
    # r = requests.post(self._subdir_url["newOrder"], headers=self._jose_hdr, data=jws_body, verify="./pebble.minica.pem")

# fetch order post as get
    # protected_hdr = {"alg": self._alg, "kid": self._account_url, "nonce": self._nonce, "url": order_url}
    # payload = ""
    # jws_body = get_jws(self._private_key, protected_hdr, payload)
    # r = requests.post(order_url, headers=self._jose_hdr, data=jws_body, verify="./pebble.minica.pem")


# retry nonce: only for local tests
# if r.json()["type"] == 'urn:ietf:params:acme:error:badNonce':
#     self._nonce = r.headers["Replay-Nonce"]
#     self.create_account()