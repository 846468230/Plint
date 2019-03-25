from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
RFC 5280: 4.2.1.6
 When the issuerAltName extension contains an Internet mail address,
   the address MUST be stored in the rfc822Name.  The format of an
   rfc822Name is a "Mailbox" as defined in Section 4.1.2 of [RFC2821].
   A Mailbox has the form "Local-part@Domain".  Note that a Mailbox has
   no phrase (such as a common name) before it, has no comment (text
   surrounded in parentheses) after it, and is not surrounded by "<" and
   ">".  Rules for encoding Internet mail addresses that include
   internationalized domain names are specified in Section 7.5.
'''
class IANEmail(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.ISSUER_ALTERNATIVE_NAME)

    def Execute(self,c):
        try:
            names = c.extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME).value
            for name in names:
                if isinstance(name,x509.RFC822Name):
                    if name.value:
                        if " " in name.value:
                            return base.LintResult(base.LintStatus.Error)
                        elif name.value[0]=='<' or name.value[-1]==')':
                            return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
   
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
        
def init():
    base.RegisterLint(base.Lint("e_ext_ian_rfc822_format_invalid","Email must not be surrounded with `<>`, and there MUST NOT be trailing comments in `()`","RFC 5280: 4.2.1.7",base.LintSource.RFC5280,Time.RFC2459Date,IANEmail()))