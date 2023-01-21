import pickle
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

class RelyingParty:
    @staticmethod
    def verify(obj, signature, certificates):
        verified = True
        need_ca = False
        for cert in certificates:
            # Basic checks on cert
            if cert.is_revoked:
                verified = False
            if cert.body.exp_date == None:  # TODO: Implement dates comparison
                verified = False
            if need_ca and cert.body.is_ca == False:
                verified = False

            # Verify obj using cert
            obj_bytes = pickle.dumps(obj)
            obj_hash = SHA256.new(obj_bytes)
            pk = DSA.import_key(cert.body.pk)
            verifier = DSS.new(pk, 'fips-186-3')
            try:
                verifier.verify(obj_hash, signature)
            except ValueError:
                verified = False

            # Prepare the next loop,
            # where cert will be verified with the next certificate
            obj = cert.body
            signature = cert.signature
            need_ca = True

        # Last certificate must be "root" and is always trusted
        return verified
