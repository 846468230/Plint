from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from cryptography.hazmat.primitives.asymmetric import rsa
'''
"BRs: 6.1.6"
RSA: The CA SHALL confirm that the value of the public exponent is an odd number equal to 3 or more. Additionally, the public exponent SHOULD be in the range between 2^16+1 and 2^256-1. The modulus SHOULD also have the following characteristics: an odd number, not the power of a prime, and have no factors smaller than 752. [Citation: Section 5.3.3, NIST SP 800-89].
'''
class rsaParsedTestsKeyExpOdd(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return isinstance(c.public_key(),rsa.RSAPublicKey)


    def Execute(self,c):
        #try:
            key = c.public_key()
            numbers = key.public_numbers()
            if numbers.e % 2 == 1 :
                return base.LintResult(base.LintStatus.Pass)
            return base.LintResult(base.LintStatus.Error)
        #except ValueError:
        #    return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_rsa_public_exponent_not_odd","RSA: Value of public exponent is an odd number equal to 3 or more.","BRs: 6.1.6",base.LintSource.CABFBaselineRequirements,Time.CABV113Date,rsaParsedTestsKeyExpOdd()))