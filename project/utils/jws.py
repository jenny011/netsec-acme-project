import uuid, json
from utils.encode import *
from utils.crypto import *

# for post reqs
# https://www.rfc-editor.org/rfc/rfc7517#appendix-A [p24]
def get_jwk_rsa(pubkey, alg):
    jwk = {"kty":"RSA", "alg":alg}
    pubNums = pubkey.public_numbers()
    jwk["e"] = int_to_base64_str(pubNums.e)
    jwk["n"] = int_to_base64_str(pubNums.n)
    # not important
    jwk["kid"] = str(uuid.uuid4())
    return jwk

# https://www.rfc-editor.org/rfc/rfc7515#section-3.2 [p7-8]
# https://www.rfc-editor.org/rfc/rfc7515#section-7.2 [p20]
def get_jws(private_key, protected_hdr, payload):
    protected_hdr_b64 = json_to_utf8_base64_str(protected_hdr)
    if payload != "":
        payload_b64 = json_to_utf8_base64_str(payload)
    else:
        payload_b64 = payload
    
    signed_part = protected_hdr_b64 + "." + payload_b64
    signature = sign(private_key, signed_part)
    signature_b64 = bytes_to_base64_str(signature)

    jws_object = {"protected": protected_hdr_b64, "payload": payload_b64, "signature": signature_b64}
    jws_body = json.dumps(jws_object)
    return jws_body

# for challenges
def get_jwk_short(pubkey):
    jwk_short = {"kty":"RSA"}
    pubNums = pubkey.public_numbers()
    jwk_short["e"] = int_to_base64_str(pubNums.e)
    jwk_short["n"] = int_to_base64_str(pubNums.n)
    return jwk_short

# [p61, 63]
def get_key_auth(token, pubkey):
    # sorted keys, compact format (no whitespaces)
    jwk_short_bytes = json.dumps(get_jwk_short(pubkey), sort_keys=True, separators=(',', ':')).encode("utf8")
    thumbprint = get_thumbprint(jwk_short_bytes)
    thumbprint_b64 = bytes_to_base64_str(thumbprint)
    key_auth = token + "." + thumbprint_b64
    return key_auth

# [p65]
def get_challenge_value(token, pubkey):
    key_auth_bytes = get_key_auth(token, pubkey).encode("utf8")
    key_auth_hash = get_thumbprint(key_auth_bytes)
    value = bytes_to_base64_str(key_auth_hash)
    return value
