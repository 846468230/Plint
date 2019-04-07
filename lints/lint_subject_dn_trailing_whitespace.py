from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,NameOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
BRs: 7.1.4.2.2
Other Subject Attributes
With the exception of the subject:organizationalUnitName (OU) attribute, optional attributes, when present within
the subject field, MUST contain information that has been verified by the CA. Metadata such as ‘.’, ‘-‘, and ‘ ‘ (i.e.
space) characters, and/or any other indication that the value is absent, incomplete, or not applicable, SHALL NOT
be used.
'''
class SubjectDNTrailingSpace(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            for commonName in c.subject:
                if commonName.value[-1]==" ":
                    return base.LintResult(base.LintStatus.Warn)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)


def init():
    base.RegisterLint(base.Lint("w_subject_dn_trailing_whitespace","AttributeValue in subject RelativeDistinguishedName sequence SHOULD NOT have trailing whitespace","AWSLabs certlint",base.LintSource.AWSLabs,Time.ZeroDate,SubjectDNTrailingSpace()))