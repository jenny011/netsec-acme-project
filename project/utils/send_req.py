import requests
from utils.encode import *
from utils.jws import *

ACME_SERVER_CERT="./pebble.minica.pem"

def send_head(url):
    return requests.head(url, verify=ACME_SERVER_CERT)

def send_get(url):
    return requests.get(url, verify=ACME_SERVER_CERT)

def send_post(url, alg, nonce, payload, headers, privkey, k, is_jwk):
    # prepare message
    if is_jwk:
        jwk = get_jwk_rsa(k, alg)
        protected_hdr = {"alg": alg, "jwk": jwk, "nonce": nonce, "url": url}
    else:
        protected_hdr = {"alg": alg, "kid": k, "nonce": nonce, "url": url}
    jws_body = get_jws(privkey, protected_hdr, payload)

    #send post req
    return requests.post(url, headers=headers, data=jws_body, verify=ACME_SERVER_CERT)


def send_post_as_get(url, alg, nonce, headers, privkey, k, is_jwk):
    # prepare message
    if is_jwk:
        jwk = get_jwk_rsa(k, alg)
        protected_hdr = {"alg": alg, "jwk": jwk, "nonce": nonce, "url": url}
    else:
        protected_hdr = {"alg": alg, "kid": k, "nonce": nonce, "url": url}
    jws_body = get_jws(privkey, protected_hdr, "")

    #send post-as-get req
    return requests.post(url, headers=headers, data=jws_body, verify=ACME_SERVER_CERT)

    