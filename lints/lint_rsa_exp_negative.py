from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from cryptography.hazmat.primitives.asymmetric import rsa
'''
'''
class rsaExpNegative(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return isinstance(c.public_key(),rsa.RSAPublicKey)


    def Execute(self,c):
        #try:
            key = c.public_key()
            numbers = key.public_numbers()
            if numbers.e < 0:
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        #except ValueError:
        #    return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_rsa_exp_negative","RSA public key exponent MUST be positive","awslabs certlint",base.LintSource.AWSLabs,Time.ZeroDate,rsaExpNegative()))