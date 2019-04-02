from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from cryptography.hazmat.primitives.asymmetric import rsa
'''
'''
class publicKeyAllowed(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True


    def Execute(self,c):
        try:
            key = c.public_key()
            return base.LintResult(base.LintStatus.Pass)
        except ValueError as e:
            if str(e)=="Certificate public key is of an unknown type":
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_public_key_type_not_allowed","Certificates MUST have RSA, DSA, or ECDSA public key type","BRs: 6.1.5",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,publicKeyAllowed()))