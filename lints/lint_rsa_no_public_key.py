from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca,primes
from cryptography.hazmat.primitives.asymmetric import rsa
'''
'''
class rsaParsedPubKeyExist(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return "RSA" in str(c.signature_algorithm_oid)


    def Execute(self,c):
        try:
            key = c.public_key()
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return base.LintResult(base.LintStatus.Error)
def init():
    base.RegisterLint(base.Lint("e_rsa_no_public_key","The RSA public key should be present","awslabs certlint",base.LintSource.AWSLabs,Time.ZeroDate,rsaParsedPubKeyExist()))