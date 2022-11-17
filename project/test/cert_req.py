import requests
from dnslib import DNSRecord


q = DNSRecord.question("a.c", qtype="A")
a = q.send("127.0.0.1", 10053)
print(DNSRecord.parse(a))
r = requests.get("https://127.0.0.1:5001/", verify=False)
print(r.headers, r.content)
