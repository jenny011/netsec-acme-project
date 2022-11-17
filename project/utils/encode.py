import base64, json

def bytes_to_str_strip(x):
    return x.decode().rstrip("=")

# https://stackoverflow.com/questions/21017698/converting-int-to-bytes-in-python-3
def int_to_base64_str(x):
    x_bytes = x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
    x_base64 = base64.urlsafe_b64encode(x_bytes)
    return bytes_to_str_strip(x_base64)

def json_to_utf8_base64_str(x):
    x_utf8 = json.dumps(x).encode("utf8")
    x_b64 = base64.urlsafe_b64encode(x_utf8)
    return bytes_to_str_strip(x_b64)

def json_to_base64_str(x):
    x_serialized = json.dumps(x)
    x_b64 = base64.urlsafe_b64encode(x_serialized)
    return bytes_to_str_strip(x_b64)

def bytes_to_base64_str(x):
    return bytes_to_str_strip(base64.urlsafe_b64encode(x))