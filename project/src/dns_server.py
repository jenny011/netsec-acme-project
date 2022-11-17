from dnslib.server import DNSServer
from dnslib.dns import RR
# https://github.com/paulc/dnslib/blob/master/dnslib/server.py

def zone_stringify(content):
    return "\n".join([f"{c['key']}. 300 IN {c['type']} {c['value']}" for c in content])

class MyResolver():
    def __init__(self, zone=[]):
        self._zone = zone
    
    def update_zone(self, zone):
        self._zone.extend(zone)

    def resolve(self,request,handler):
        reply = request.reply()
        reply.add_answer(*RR.fromZone(zone_stringify(self._zone)))
        return reply

class DNS_SERVER():
    def __init__(self, host, port, zone=[]):
        self._host = host
        self._port = port
        self.resolver = MyResolver(zone)
        self.server = DNSServer(self.resolver, port=self._port, address=self._host)
        
    def update_zone(self, zone):
        self.server.server.resolver.update_zone(zone)

    def run(self):
        self.server.start_thread()
    
    def stop(self):
        self.server.stop()