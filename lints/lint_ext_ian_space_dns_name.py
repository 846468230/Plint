from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
RFC 5280: 4.2.1.7
When the issuerAltName extension contains a domain name system
label, the domain name MUST be stored in the dNSName (an IA5String).
The name MUST be in the "preferred name syntax", as specified by
Section 3.5 of [RFC1034] and as modified by Section 2.1 of
[RFC1123].  Note that while uppercase and lowercase letters are
allowed in domain names, no significance is attached to the case.  In
addition, while the string " " is a legal domain name, subjectAltName
extensions with a dNSName of " " MUST NOT be used.  Finally, the use
of the DNS representation for Internet mail addresses
(subscriber.example.com instead of subscriber@example.com) MUST NOT
be used; such identities are to be encoded as rfc822Name.  Rules for
encoding internationalized domain names are specified in Section 7.2.
'''
class IANSpace(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.ISSUER_ALTERNATIVE_NAME)

    def Execute(self,c):
        try:
            names = c.extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME).value
            for name in names:
                if isinstance(name,x509.DNSName):
                    if name.value ==" ":
                        return base.LintResult(base.LintStatus.Error)
            return  base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except UnicodeDecodeError:
            return base.LintResult(base.LintStatus.Error)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
        
def init():
    base.RegisterLint(base.Lint("e_ext_ian_space_dns_name","dNSName ' ' MUST NOT be used","RFC 5280: 4.2.1.6",base.LintSource.RFC5280,Time.RFC2459Date,IANSpace()))