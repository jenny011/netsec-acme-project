import argparse
import multiprocessing
from multiprocessing import Process
from src.acme_client import *
from src.dns_server import *
from src.http_server import *
from src.cert_server import *
from src.shutdown_server import *

parser = argparse.ArgumentParser(description='acme project')
parser.add_argument('--cType', type=str, help='challenge type', required=True)
parser.add_argument('--dir_url', type=str, help='acme server dir url', required=True)
parser.add_argument('--record', type=str, help='ipv4 addr', required=True)
parser.add_argument('--domains', type=str, nargs='+', help='domains', required=True)
parser.add_argument('--revoke', action='store_true')

if __name__ == "__main__":
    # spawn doesn't work for Flask
    multiprocessing.set_start_method("fork")

    args = parser.parse_args()
    domains = args.domains
    record = args.record

    dns_port = 10053
    http_port = 5002
    cert_port = 5001
    shutdown_port = 5003

    # any IP
    host = "0.0.0.0"
    CERTS_DIR = "certs/"
    CERT_FILE = "cert.pem"
    
    KEYS_DIR = "keys/"
    CERT_KEY_FILE = "cert_key.pem"
    
    # keep dns server running and keep all the records: for extra dns_server tests (FAQ)
    # dns_server should always resolve client domain to "record"
    zone = [{"key": domain, "value": record, "type": 'A'} for domain in domains]
    debug_print(zone)
    dns_server = DNS_SERVER(host, dns_port, zone)
    dns_server.run()

    # ACME protocol procedure
    client = ACME_CLIENT(args.dir_url, CERTS_DIR, CERT_FILE, KEYS_DIR, CERT_KEY_FILE, dns_server)
    success = client.run(host, http_port, args.cType, domains, args.revoke)

    # run shutdown_server in the background
    # https://stackoverflow.com/questions/68885585/wait-for-value-then-stop-server-after-werkzeug-server-shutdown-is-deprecated
    q = multiprocessing.Queue()
    shutdown_server = SHUTDOWN_SERVER(host, shutdown_port, q)
    shutdown_prc = Process(target=shutdown_server.run)
    shutdown_prc.start()

    if success:
        print("ACME protocol done")
        cert_server = CERT_SERVER(record, cert_port, CERTS_DIR + CERT_FILE, KEYS_DIR + CERT_KEY_FILE)
        cert_prc = Process(target=cert_server.run)
        cert_prc.start()

        # keep prcs alive until shutdown server gets shutdown request
        SIG_SHUTDOWN = q.get(block=True)
        cert_prc.terminate()
        cert_prc.join()
    else:
        print("Certificate request failed, quit")
        
    # clean up
    dns_server.stop()
    shutdown_prc.terminate()
    shutdown_prc.join()  
    