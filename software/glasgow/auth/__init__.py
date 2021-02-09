from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

def signature_from_bytes(raw_signature):
    r = int.from_bytes(raw_signature[:32], "big")
    s = int.from_bytes(raw_signature[32:], "big")
    signature = encode_dss_signature(r, s)