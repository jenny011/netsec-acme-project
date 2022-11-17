import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from utils.encode import *
from utils.debug import *

# utils for csr and cert

# convert PEM bytes to DER
def pem_to_der(cert_bytes):
    cert = x509.load_pem_x509_certificate(cert_bytes)
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return cert_der


# generate CSR in DER format
# https://cryptography.io/en/latest/x509/tutorial/#creating-a-certificate-signing-request-csr
def generate_csr(priv_key, domains, cname):
    csr = x509.CertificateSigningRequestBuilder()\
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cname),
        ]))\
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
            critical=False,
        )\
        .sign(priv_key, hashes.SHA256())

    return csr.public_bytes(serialization.Encoding.DER)

def generate_csr_b64(priv_key, domains, cname):
    return bytes_to_base64_str(generate_csr(priv_key, domains, cname))


# save in PEM format [p46]
# https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.public_bytes
def save_cert_to_file(cert_bytes, CERTS_DIR, fname):
    if not os.path.isdir(CERTS_DIR):
        os.makedirs(CERTS_DIR)
    debug_print(CERTS_DIR, fname, cert_bytes)
    with open(CERTS_DIR + fname, 'wb') as f:
        f.write(cert_bytes)

# load to DER format [p46] 
def load_cert_from_file(certPath):
    if os.path.isfile(certPath):
        with open(certPath, 'rb') as f:
            cert_bytes = f.read()
            return pem_to_der(cert_bytes)

def load_cert_b64(certPath):
    return bytes_to_base64_str(load_cert_from_file(certPath))

# https server return value
def load_cert_from_file_raw(certPath):
    if os.path.isfile(certPath):
        with open(certPath, 'rb') as f:
            return f.read()