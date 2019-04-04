from lints import base
from cryptography import x509
from util.time import Time
from util import ca
'''
'''
class serialNumberLowEntropy(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            SerialNumber = c.serial_number
            if SerialNumber.bit_length() < 64:
                return base.LintResult(base.LintStatus.Warn)
            else:
                return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)


def init():
    base.RegisterLint(base.Lint("w_serial_number_low_entropy","Effective September 30, 2016, CAs SHALL generate non‐sequential Certificate serial numbers greater than zero (0) containing at least 64 bits of output from a CSPRNG.","BRs: 7.1",base.LintSource.CABFBaselineRequirements,Time.CABSerialNumberEntropyDate,serialNumberLowEntropy()))