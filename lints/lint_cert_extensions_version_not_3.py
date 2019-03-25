from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca,oid
'''
4.1.2.1.  Version
   This field describes the version of the encoded certificate. When
   extensions are used, as expected in this profile, version MUST be 3
   (value is 2). If no extensions are present, but a UniqueIdentifier
   is present, the version SHOULD be 2 (value is 1); however, the version
   MAY be 3.  If only basic fields are present, the version SHOULD be 1
   (the value is omitted from the certificate as the default value);
   however, the version MAY be 2 or 3.

   Implementations SHOULD be prepared to accept any version certificate.
   At a minimum, conforming implementations MUST recognize version 3 certificates.
4.1.2.9.  Extensions
   This field MUST only appear if the version is 3 (Section 4.1.2.1).
   If present, this field is a SEQUENCE of one or more certificate
   extensions. The format and content of certificate extensions in the
   Internet PKI are defined in Section 4.2.
'''
class CertExtensionsVersonNot3(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return True
    
    def Execute(self,c):
        try:
            if c.version !=x509.Version.v3 and len(c.extensions) !=0 :
                return  base.LintResult(base.LintStatus.Error)
            else:
                return  base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)


def init():
    base.RegisterLint(base.Lint("e_cert_extensions_version_not_3","The extensions field MUST only appear in version 3 certificates","RFC 5280: 4.1.2.9",base.LintSource.RFC5280,Time.RFC2459Date,CertExtensionsVersonNot3()))