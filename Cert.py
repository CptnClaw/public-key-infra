
class Cert():
    def __init__(self, name, pk, is_ca, exp_date):
        self.name = name
        self.pk = pk
        self.is_ca = is_ca
        self.exp_date = exp_date
        self.issuer = None
        self.signature = None


