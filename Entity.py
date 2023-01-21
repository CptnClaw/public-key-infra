import pickle
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Cert import CertBody

class Entity:
    def __init__(self, name):
        self.name = name
        self.sk = DSA.generate(2048)
        self.pk = self.sk.publickey()
        self.signer = DSS.new(self.sk, 'fips-186-3')
        self.is_ca = False
        self.cert = None

    def sign(self, obj):
        obj_bytes = pickle.dumps(obj)
        obj_hash = SHA256.new(obj_bytes)
        signature = self.signer.sign(obj_hash)
        return signature

    def gen_cert_body(self, exp_date):
        return CertBody(self.name, self.pk.exportKey(), self.is_ca, exp_date)


