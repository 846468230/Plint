from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
from cryptography.hazmat.primitives import hashes
'''
BRs: 7.1.3
SHA‐1	MAY	be	used	with	RSA	keys	in	accordance	with	the	criteria	defined	in	Section	7.1.3.
'''
class sigAlgTestsSHA1(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            signature_hash_algorithm = c.signature_hash_algorithm
            if isinstance(signature_hash_algorithm,hashes.SHA1):
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_or_sub_ca_using_sha1","CAs MUST NOT issue any new Subscriber certificates or Subordinate CA certificates using SHA-1 after 1 January 2016","BRs: 7.1.3",base.LintSource.CABFBaselineRequirements,Time.NO_SHA1,sigAlgTestsSHA1()))