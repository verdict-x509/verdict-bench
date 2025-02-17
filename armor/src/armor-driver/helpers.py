from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.backends import default_backend

def hex_to_int(inp):
    res = ""
    for x in inp.strip().split(" "):
        res = res + str(int(x, 16)) + " "
    return res.strip()

def int_to_hex(inp):
    res = ""
    for x in inp.strip().split(" "):
        res = res + "" + '{:02x}'.format(int(x))
    return res

def hex_to_bytes(inp):
    return bytes.fromhex(inp)


def int_to_Bytes(inp):
    return hex_to_bytes(int_to_hex(inp))

tbs_bytes = []
sign_oids = []
signatures = []
pks = []

sign_oid_map = {
    "6 9 42 134 72 134 247 13 1 1 11": "sha256WithRSAEncryption",
    "6 9 42 134 72 134 247 13 1 1 12": "sha384WithRSAEncryption",
    "6 9 42 134 72 134 247 13 1 1 13": "sha512WithRSAEncryption",
    "6 9 42 134 72 134 247 13 1 1 14": "sha224WithRSAEncryption",
    "6 9 42 134 72 134 247 13 1 1 5": "sha1WithRSAEncryption",
    '6 8 42 134 72 206 61 4 3 1': 'ecdsa-with-SHA224',
    '6 8 42 134 72 206 61 4 3 2': 'ecdsa-with-SHA256',
    '6 8 42 134 72 206 61 4 3 3': 'ecdsa-with-SHA384',
    '6 8 42 134 72 206 61 4 3 4': 'ecdsa-with-SHA512'
}

sign_oid_map_insecure = {
    "6 9 42 134 72 134 247 13 1 1 2": "md2WithRSAEncryption",
    "6 9 42 134 72 134 247 13 1 1 3": "md4WithRSAEncryption",
    "6 9 42 134 72 134 247 13 1 1 4": "md5WithRSAEncryption"
}


def readData(lines):
    tbs_bytes = []
    sign_oids = []
    signatures = []
    pks = []

    for i in range(0, len(lines)):
        if (i % 6 == 0):  # tbs bytes
            tbs_bytes.append(int_to_Bytes(lines[i].strip()))
        elif (i % 6 == 1):  # signature
            if lines[i].strip().startswith("0 "):  ## 0 as padding byte
                lines_i_0_stripped = lines[i].strip()[2:]
                signatures.append(int_to_Bytes(lines_i_0_stripped))
            else:  ## without padding byte
                signatures.append(int_to_Bytes(lines[i].strip()))
        elif (i % 6 == 2):  # pk
            pks.append(load_der_public_key(int_to_Bytes(lines[i].strip()), backend=default_backend()))
        elif (i % 6 == 3):  # sign oid
            sign_oids.append(lines[i].strip())
        elif (i % 6 == 4):  # eku purposes
            continue
