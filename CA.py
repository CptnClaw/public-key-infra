from Entity import Entity

class CA(Entity):
    def issue(self, certificate):
        certificate.issuer = self.name
        certificate.signature = ""

