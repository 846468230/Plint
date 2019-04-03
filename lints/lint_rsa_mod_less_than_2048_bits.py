from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from datetime import timedelta
from util import ca,primes
from cryptography.hazmat.primitives.asymmetric import rsa
'''
'''
class rsaParsedTestsKeySize(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return isinstance(c.public_key(),rsa.RSAPublicKey) and c.not_valid_after > Time.NoRSA1024Date - timedelta(days=1)

    def Execute(self,c):
        #try:
            key = c.public_key()
            if key.key_size < 2048:
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        #except ValueError:
        #    return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_rsa_mod_less_than_2048_bits","For certificates valid after 31 Dec 2013, all certificates using RSA public key algorithm MUST have 2048 bits of modulus","BRs: 6.1.5",base.LintSource.CABFBaselineRequirements,Time.ZeroDate,rsaParsedTestsKeySize()))