from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from cryptography.hazmat.primitives.asymmetric import rsa
'''
'''
class subCaModSize(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        issueDate = c.not_valid_before
        endDate = c.not_valid_after
        key = c.public_key()
        return isinstance(key, rsa.RSAPublicKey) and ca.IsSubCA(c) and issueDate < Time.NoRSA1024RootDate and endDate < Time.NoRSA1024Date


    def Execute(self,c):
        try:
            key = c.public_key()
            if key.key_size < 1024:
                return base.LintResult(base.LintStatus.Error)
            else:
                return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_old_sub_ca_rsa_mod_less_than_1024_bits","In a validity period beginning on or before 31 Dec 2010 and ending on or before 31 Dec 2013, subordinate CA certificates using RSA public key algorithm MUST use a 1024 bit modulus","BRs: 6.1.5",base.LintSource.CABFBaselineRequirements,Time.ZeroDate,subCaModSize()))