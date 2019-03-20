from lints import base
from cryptography import x509
from util.time import Time
from util import ca
from cryptography.hazmat.primitives.asymmetric import dsa
class dsaImproperSize(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return isinstance(c.public_key(),dsa.DSAPublicKey)
    
    def Execute(self,c):
        try:
            dsakey = c.public_key()
            Numbers = dsakey.public_numbers().parameter_numbers
            if (Numbers.p.bit_length(),Numbers.q.bit_length()) in ((2048,224),(2048,256),(3072,256)) :
                return base.LintResult(base.LintStatus.Pass)
            else:
                return base.LintResult(base.LintStatus.Warn)
        except ValueError:
            return  base.LintResult(base.LintStatus.NA)
            


def init():
    base.RegisterLint(base.Lint("e_dsa_improper_modulus_or_divisor_size","Certificates MUST meet the following requirements for algorithm type and key size: L=2048, N=224,256 minimum DSA","BRs: 6.1.5",base.LintSource.CABFBaselineRequirements,Time.ZeroDate,dsaImproperSize()))