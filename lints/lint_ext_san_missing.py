from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
BRs: 7.1.4.2.1
Subject Alternative Name Extension
Certificate Field: extensions:subjectAltName
Required/Optional: Required
'''
class SANMissing(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return not ca.IsCACert(c)

    def Execute(self,c):
        try:
            if ca.IsExtInCert(c,ExtensionOID.SUBJECT_ALTERNATIVE_NAME):
                return base.LintResult(base.LintStatus.Pass)
            else:
                return base.LintResult(base.LintStatus.Error)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Error)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_ext_san_missing","Subscriber certificates MUST contain the Subject Alternate Name extension","BRs: 7.1.4.2.1",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,SANMissing()))