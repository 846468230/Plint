from lints import base
from cryptography import x509
from util.time import Time
from util import ca
from cryptography.hazmat.primitives.asymmetric import dsa
class dsaUniqueCorrectRepresentation(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return isinstance(c.public_key(),dsa.DSAPublicKey)
    
    def Execute(self,c):
        try:
            dsakey = c.public_key()
            Numbers = dsakey.public_numbers().parameter_numbers
            if Numbers.g >= 2 and Numbers.g<= Numbers.p-2 :
                return base.LintResult(base.LintStatus.Pass)
            else:
                return base.LintResult(base.LintStatus.Error)
        except ValueError:
            return  base.LintResult(base.LintStatus.NA)
            


def init():
    base.RegisterLint(base.Lint("e_dsa_unique_correct_representation","DSA: Public key value has the unique correct representation in the field, and that the key has the correct order in the subgroup","BRs: 6.1.6",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,dsaUniqueCorrectRepresentation()))