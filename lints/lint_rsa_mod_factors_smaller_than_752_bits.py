from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca,primes
from cryptography.hazmat.primitives.asymmetric import rsa
'''
6.1.6. Public Key Parameters Generation and Quality Checking
RSA: The CA SHALL confirm that the value of the public exponent is an odd number equal to 3 or more. Additionally, the public exponent SHOULD be in the range between 216+1 and 2256-1. The modulus SHOULD also have the following characteristics: an odd number, not the power of a prime, and have no factors smaller than 752. [Citation: Section 5.3.3, NIST SP 800‐89].
'''
class rsaModSmallFactor(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return isinstance(c.public_key(),rsa.RSAPublicKey)


    def Execute(self,c):
        #try:
            key = c.public_key()
            module = key.public_numbers().n
            if primes.PrimeNoSmallerThan752(module):
                return base.LintResult(base.LintStatus.Pass)
            return base.LintResult(base.LintStatus.Warn)
        #except ValueError:
        #    return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("w_rsa_mod_factors_smaller_than_752","RSA: Modulus SHOULD also have the following characteristics: no factors smaller than 752","BRs: 6.1.6",base.LintSource.CABFBaselineRequirements,Time.CABV113Date,rsaModSmallFactor()))