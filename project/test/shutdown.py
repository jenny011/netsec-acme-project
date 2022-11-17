import requests

r = requests.get("http://127.0.0.1:5003/shutdown")
print(r.headers)
