from lints import base#错误的规则
from cryptography import x509
from util.time import Time
from util import ca
from cryptography.hazmat.primitives.asymmetric import dsa
class dsaTooShort(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return isinstance(c.public_key(),dsa.DSAPublicKey)
    #L=Numbers.p.bit_length() N=Numbers.q.bit_length()
    def Execute(self,c):
        try:
            dsakey = c.public_key()
            Numbers = dsakey.public_numbers().parameter_numbers
            if Numbers.p.bit_length() >= 2048 and Numbers.q.bit_length() >=224: #which value in Zlint is q.bit_length() >=244 
                return base.LintResult(base.LintStatus.Pass)
            else:
                return base.LintResult(base.LintStatus.Error)
        except ValueError:
            return  base.LintResult(base.LintStatus.NA)
            


def init():
    base.RegisterLint(base.Lint("e_dsa_shorter_than_2048_bits","DSA modulus size must be at least 2048 bits","BRs: 6.1.5",base.LintSource.CABFBaselineRequirements,Time.ZeroDate,dsaTooShort()))