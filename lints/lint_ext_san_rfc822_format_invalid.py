from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
RFC 5280: 4.2.1.6
 When the subjectAltName extension contains an Internet mail address,
   the address MUST be stored in the rfc822Name.  The format of an
   rfc822Name is a "Mailbox" as defined in Section 4.1.2 of [RFC2821].
   A Mailbox has the form "Local-part@Domain".  Note that a Mailbox has
   no phrase (such as a common name) before it, has no comment (text
   surrounded in parentheses) after it, and is not surrounded by "<" and
   ">".  Rules for encoding Internet mail addresses that include
   internationalized domain names are specified in Section 7.5.
'''
class invalidEmail(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    def Execute(self,c):
        try:
            SANs = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            for SAN in SANs:
                if isinstance(SAN,x509.RFC822Name):
                    if SAN.value== "":
                        continue
                    if " " in SAN.value:
                        return  base.LintResult(base.LintStatus.Error)
                    elif SAN.value[0] == '<' or SAN.value[-1]== ')':
                        return  base.LintResult(base.LintStatus.Error)
            return  base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_ext_san_rfc822_format_invalid","Email MUST NOT be surrounded with `<>`, and there must be no trailing comments in `()`","RFC 5280: 4.2.1.6",base.LintSource.RFC5280,Time.RFC2459Date,invalidEmail()))