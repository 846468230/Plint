from lints import base
from cryptography import x509
from util.time import Time
from util import ca
from cryptography.hazmat.primitives import hashes
'''
'''
class signatureAlgorithmNotSupported(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            if isinstance(c.signature_hash_algorithm,hashes.SHA1) or isinstance(c.signature_hash_algorithm,hashes.SHA256) or isinstance(c.signature_hash_algorithm,hashes.SHA384) or isinstance(c.signature_hash_algorithm,hashes.SHA512) :
                return base.LintResult(base.LintStatus.Pass)
            else:
                return base.LintResult(base.LintStatus.Error)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)


def init():
    base.RegisterLint(base.Lint("e_signature_algorithm_not_supported","Certificates MUST meet the following requirements for algorithm Source: SHA-1*, SHA-256, SHA-384, SHA-512","BRs: 6.1.5",base.LintSource.CABFBaselineRequirements,Time.ZeroDate,signatureAlgorithmNotSupported()))