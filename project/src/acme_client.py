import time
from multiprocessing import Process
from utils.jws import *
from utils.crypto import *
from utils.debug import *
from utils.send_req import *
from utils.cert import *
from src.dns_server import *
from src.http_server import *

# '_' attributes are intended to be generated and used internally
# '_' methods are intended to be used internally
# APIs for main logic are exposed to run()
# run() API is exposed to main

class ACME_CLIENT():
    def __init__(self, dir_url, CERTS_DIR, CERT_FILE, KEYS_DIR, CERT_KEY_FILE, dns_server):
        self.dir_url = dir_url
        self.dns_server = dns_server
        # crypto [p85]
        self.certs_dir = CERTS_DIR
        self.cert_file = CERT_FILE
        # https://www.rfc-editor.org/rfc/rfc7518#section-3.1
        self._alg="RS256"
        self._jose_hdr = {"Content-Type": "application/jose+json"}
        self._private_key, self._public_key = get_key_pair()
        self._cert_priv_key, self._cert_pub_key = get_key_pair(KEYS_DIR, CERT_KEY_FILE)
        self._nonce = ""
        # account
        self._subdir_url = {}
        self._account_url= ""
        self._order = {}
        # init
        self._get_directory()
        self._get_nonce()
    
    def _send_post(self, url, is_jwk, payload=None, hdr=None):
        if is_jwk:
            jwk_or_kid = self._public_key
        else:
            jwk_or_kid = self._account_url
        
        if hdr is None:
            hdr = self._jose_hdr

        if payload is None:
            return send_post_as_get(url, self._alg, self._nonce, 
                hdr, self._private_key, jwk_or_kid, is_jwk=is_jwk)
        else:
            return send_post(url, self._alg, self._nonce, payload, 
                hdr, self._private_key, jwk_or_kid, is_jwk=is_jwk)     

    def _get_directory(self):
        r = send_get(self.dir_url)
        if r.status_code == 200:
            rBody = r.json()
            self._subdir_url["newNonce"] = rBody["newNonce"]
            self._subdir_url["newAccount"] = rBody["newAccount"]
            self._subdir_url["newOrder"] = rBody["newOrder"]
            self._subdir_url["revokeCert"] = rBody["revokeCert"]
            self._subdir_url["keyChange"] = rBody["keyChange"]
            if "newAuthz" in rBody:
                self._subdir_url["newAuthz"] = rBody["newAuthz"]
            debug_print("-get_dir", self._subdir_url)
        else:
            print("-get_dir_err", r.headers, r.json())

    def _get_nonce(self):
        r = send_head(self._subdir_url["newNonce"])
        if r.status_code == 200:
            self._nonce = r.headers["Replay-Nonce"]
        else:
            print("-get_nonce_err", r.headers, r.json())

    def create_account(self):
        payload = {"termsOfServiceAgreed": True}
        r = self._send_post(self._subdir_url["newAccount"], True, payload)
        debug_print("-create_acct", r.headers, r.json())

        # account exists or account created
        if r.status_code == 200 or r.status_code == 201:
            self._nonce = r.headers["Replay-Nonce"]
            self._account_url = r.headers["Location"]
        else:
            print("-create_acct_err", r.headers, r.json())

    def submit_order(self, domains):
        identifiers = []
        for domain in domains:
            identifiers.append({"type":"dns", "value":domain})
        payload = {"identifiers":identifiers}
        r = self._send_post(self._subdir_url["newOrder"], False, payload)
        debug_print("-submit_order", r.headers, r.json())

        # order created: new order object [p45]
        if r.status_code == 201:
            self._nonce = r.headers["Replay-Nonce"]
            self._order["loc"] = r.headers["Location"]
            # receive challenge
            rBody = r.json()
            self._order["finalize"] = rBody["finalize"]
            self._order["authorizations"] = rBody["authorizations"]
        else:
            print("-submit_order_err", r.headers, r.json())

    def do_challenges(self, host, http_port, cType):
        if cType == "http01":
            return self._http_challenge(host, http_port)
        elif cType == "dns01":
            return self._dns_challenge()
        else:
            print("Unknown challenge:", cType)
            return False

    # [p63]
    def _http_challenge(self, host, http_port):
        # config http server
        http_server = HTTP_SERVER(host, http_port)
        challenges = []
        for authz_url in self._order["authorizations"]:
            challenge = self._fetch_challenge(authz_url, "http-01")
            if challenge == {}:
                return False
            challenges.append(challenge)
        
            # use key auth string
            value = get_key_auth(challenge["content"]["token"], self._public_key)
            http_server.save_key_auth(challenge["content"]["token"], value)

        # start http server 
        http_prc = Process(target=http_server.run)
        http_prc.start()
        for challenge in challenges:
            # respond to challenge, wait for authz valid or invalid
            self._respond_to_challenge("http01", challenge)    
            if not self._poll_for_authz_status(challenge["authz"]):
                return False
        http_prc.terminate()
        http_prc.join()
        return True

    # [p65]
    def _dns_challenge(self):
        # caution: updating zone with records for all authzs at once does not work for {"*.a", "a"}
        for authz_url in self._order["authorizations"]:
            challenge = self._fetch_challenge(authz_url, "dns-01")
            if challenge == {}:
                return False

            # use key auth thumbprint
            value = get_challenge_value(challenge["content"]["token"], self._public_key)
            zone = [{"key": "_acme-challenge." + challenge["domain"], "value": value, "type": 'TXT'}]
            debug_print(zone)
            self.dns_server.update_zone(zone)
            
            # respond to challenge, wait for authz valid or invalid
            self._respond_to_challenge("dns01", challenge)
            if not self._poll_for_authz_status(challenge["authz"]):
                return False
        return True

    def _respond_to_challenge(self, cType, challenge):
        # respond to challenge
        r = self._send_post(challenge["content"]["url"], False, {})
        debug_print(f"-{cType}_challenge_res", r.headers, r.json())
    
        if r.status_code == 200:
            self._nonce = r.headers["Replay-Nonce"]
            # receive updated order object
            rBody = r.json()
            debug_print(f"{cType}_challenge status: {challenge['domain']}, {rBody['status']}")
        else:
            print(f"-{cType}_challenge_res_err", r.headers, r.json())

    def finalize_order(self, domains):
        csr = generate_csr_b64(self._cert_priv_key, domains, domains[0])
        payload = {"csr":csr}
        r = self._send_post(self._order["finalize"], False, payload)
        debug_print("-finalize_order", r.headers, r.json())

        #[p47]
        if r.status_code == 200 or r.status_code == 403:
            self._nonce = r.headers["Replay-Nonce"]
            return self._poll_for_order_status()
        else:
            # side note: errcode "badCSR", reason in "detail" field
            # the order is left in "ready" state, amend the CSR and send finalize req again
            print("-finalize_order_err", r.headers, r.json())
            return False

    # [p50]
    def download_cert(self):
        hdr = self._jose_hdr
        hdr["Accept"] = "application/pem-certificate-chain"
        r = self._send_post(self._order["cert_url"], False, payload=None, hdr=hdr)
        debug_print("-download_cert", r.headers, r.content)

        if r.status_code == 200:
            self._nonce = r.headers["Replay-Nonce"]
            # cert = r.content = response content in bytes
            save_cert_to_file(r.content, self.certs_dir, self.cert_file)
            return True
        else:
            print("-download_cert_err", r.headers, r.content)
            return False

    # ------------------------ fetch object ------------------------
    # [p52]
    def _fetch_challenge(self, authz_url, cType):
        r = self._send_post(authz_url, False)
        debug_print("-fetch_challenge", authz_url, r.headers, r.json())

        challenge = {}
        if r.status_code == 200:
            self._nonce = r.headers["Replay-Nonce"]
            # receive challenge object
            rBody = r.json()
            challenges = rBody["challenges"]
            for c in challenges:
                if c["type"] == cType:
                    challenge["content"] = c
            if challenge != {}:
                identifier = rBody["identifier"]
                domain = identifier["value"]
                challenge["domain"] = domain
                challenge["cType"] = cType
                challenge["authz"] = authz_url            
        else:
            print("-fetch_challenge_err", authz_url, r.headers, r.json())
        return challenge

    def _fetch_authz(self, authz_url):
        r = self._send_post(authz_url, False)
        debug_print("-fetch_authz", r.headers, r.json())

        if r.status_code == 200:
            self._nonce = r.headers["Replay-Nonce"]
            # receive authz object
            rBody = r.json()
            return rBody["status"]
        else:
            print("-fetch_authz_err", r.headers, r.json())

    def _fetch_order(self, order_url):
        r = self._send_post(order_url, False)
        debug_print("-fetch_order", r.headers, r.json())

        if r.status_code == 200:
            self._nonce = r.headers["Replay-Nonce"]
            # receive order
            rBody = r.json()
            status = rBody["status"]
            if status == "ready":
                self._order["finalize"] = rBody["finalize"]
            elif status == "valid":
                self._order["cert_url"] = rBody["certificate"]
            return status
        else:
            print("-fetch_order_err", r.headers, r.json())

    # ------------------------ poll for status ------------------------
    # AUTHZ STATUS [p30]
    # pending: poll 
    # valid: one of the challenges of this authz is fulfilled
    # invalid, expired, deactivated, revoked: abandon the order
    def _poll_for_authz_status(self, authz_url):
        # hard timeout: 60sec
        for i in range(20):
            status = self._fetch_authz(authz_url)
            if status == "valid":
                return True
            elif status != "pending":
                return False
            time.sleep(3)
        return False

    # ORDER STATUS [p31]
    # ready, pending, processing: poll
    # valid: download the cert from the url at "certificate" field
    # invalid: abandon the order
    def _poll_for_order_status(self):
        # hard timeout: 60sec
        for i in range(20):
            status = self._fetch_order(self._order["loc"])
            if status == "valid":
                return True
            elif status == "invalid":
                return False
            time.sleep(3)
        return False
    
    # [p57]
    def revoke_cert(self):
        # load cert form file, DER binary format to b64 str stripped
        cert = load_cert_b64(self.certs_dir + self.cert_file)
        payload = {"certificate":cert}
        r = self._send_post(self._subdir_url["revokeCert"], False, payload)
        debug_print("-revoke_cert", r.headers)

        if r.status_code == 200:
            self._nonce = r.headers["Replay-Nonce"]
        else:
            print("-revoke_cert_err", r.headers, r.json())


    # ------------------------ run acme client ------------------------
    def run(self, host, http_port, cType, domains, revoke=False):
        self.create_account()
        self.submit_order(domains)

        # invalid: order rejected, remove order from storage, then exit
        ret = False
        if self.do_challenges(host, http_port, cType):
            if self.finalize_order(domains):
                if self.download_cert():
                    if revoke:
                        print("Immediately revoke certificate")
                        self.revoke_cert()
                    ret = True
        self._order = {}
        return ret
