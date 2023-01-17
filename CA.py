from Entity import Entity
from Cert import Cert

class CA(Entity):
    def __init__(self, name):
        super().__init__(name)
        self.is_ca = True

    def issue(self, certbody):
        # This CA is so nice. It signs every certificate it gets, no questions asked.
        signature = self.sign(certbody)
        return Cert(certbody, self.name, signature)


