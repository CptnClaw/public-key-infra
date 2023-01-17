from Cert import Cert
from Entity import Entity
from CA import CA
from RelyingParty import RelyingParty


NEXT_MONTH = ''  # TODO: Implement dates
NEXT_YEAR = ''

# List containing every certificate issued ever
cache = []

def gen_cert(entity, exp_date, ca=None):

    # Let ca issue a certificate and apply it to entity
    body = entity.gen_cert_body(exp_date)
    if ca != None:
        cert = ca.issue(body)
    else:
        cert = Cert(body, issuer=None, signature=None)
    entity.cert = cert

    # Add to cache
    global cache
    cache += [cert]


def lookup_cert(name):
    for cert in cache:
        if cert.body.name == name:
            return cert
    raise KeyError


def gen_cert_sequence(start_cert):
    cert = start_cert
    sequence = [cert]
    while cert.issuer != None:
        cert = lookup_cert(cert.issuer)
        sequence += [cert]
    return sequence


if __name__ == '__main__':
    
    # Create root CA
    root = CA('root')
    # It has a dummy cert (not signed by anyone)
    gen_cert(root, NEXT_YEAR, None)
    
    # Create il CA, signed by root
    il = CA('il')
    gen_cert(il, NEXT_MONTH, root)

    # Create ac.il CA, signed by il
    ac = CA('ac.il')
    gen_cert(ac, NEXT_MONTH, il)

    # Create huji.ac.il CA, signed by ac.il
    huji = CA('huji.ac.il')
    gen_cert(huji, NEXT_MONTH, ac)

    # Create several entities signed by huji.ac.il
    www = Entity('www.huji.ac.il')
    math = Entity('mathematics.huji.ac.il')
    moodle = Entity('moodle.huji.ac.il')
    gen_cert(www, NEXT_MONTH, huji)
    gen_cert(math, NEXT_MONTH, huji)
    gen_cert(moodle, NEXT_MONTH, huji)

    # Sign some IP addresses
    ip_www = '128.139.7.8'
    ip_math = '128.139.7.33'
    ip_moodle = '132.65.118.159'
    sgn1, cert1 = www.sign(ip_www)
    sgn2, cert2 = math.sign(ip_math)
    sgn3, cert3 = moodle.sign(ip_moodle)

    # Verify 
    cert_seq1 = gen_cert_sequence(cert1)
    verify1 = RelyingParty.verify(ip_www, sgn1, cert_seq1)
    cert_seq2 = gen_cert_sequence(cert2)
    verify2 = RelyingParty.verify(ip_www, sgn2, cert_seq2)
    cert_seq3 = gen_cert_sequence(cert3)
    verify3 = RelyingParty.verify(ip_www, sgn3, cert_seq3)

    print(verify1, verify2, verify3)



