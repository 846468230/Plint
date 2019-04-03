from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from cryptography.hazmat.primitives.asymmetric import rsa
'''
'''
class rsaParsedTestsExpInRange(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return isinstance(c.public_key(),rsa.RSAPublicKey)


    def Execute(self,c):
        #try:
            key = c.public_key()
            numbers = key.public_numbers()
            if numbers.e > 65535 and numbers.e < 2**256 :
                return base.LintResult(base.LintStatus.Pass)
            return base.LintResult(base.LintStatus.Warn)
        #except ValueError:
        #    return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("w_rsa_public_exponent_not_in_range","RSA: Public exponent SHOULD be in the range between 2^16 + 1 and 2^256 - 1","BRs: 6.1.6",base.LintSource.CABFBaselineRequirements,Time.CABV113Date,rsaParsedTestsExpInRange()))