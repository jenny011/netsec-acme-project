pebble -config ./test/config/pebble-config.json --dnsserver 127.0.0.1:10053


run dns01 --dir https://localhost:14000/dir --record 127.0.0.1 --domain netsec.ethz.ch
run dns01 --dir https://localhost:14000/dir --record 127.0.0.1 --domain netsec.ethz.ch --domain my.example.org
run dns01 --dir https://localhost:14000/dir --record 127.0.0.1 --domain *.ethz.ch
run dns01 --dir https://localhost:14000/dir --record 127.0.0.1 --domain *.ethz.ch --domain my.example.org


run http01 --dir https://localhost:14000/dir --record 127.0.0.1 --domain netsec.ethz.ch
run http01 --dir https://localhost:14000/dir --record 127.0.0.1 --domain netsec.ethz.ch --domain my.example.org
run http01 --dir https://localhost:14000/dir --record 127.0.0.1 --domain *.ethz.ch
run http01 --dir https://localhost:14000/dir --record 127.0.0.1 --domain *.ethz.ch --domain my.example.org