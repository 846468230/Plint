from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,ExtendedKeyUsageOID
from util.time import Time
from util import ca
'''
RFC 5280: 4.2.1.12
If a CA includes extended key usages to satisfy such applications,
   but does not wish to restrict usages of the key, the CA can include
   the special KeyPurposeId anyExtendedKeyUsage in addition to the
   particular key purposes required by the applications.  Conforming CAs
   SHOULD NOT mark this extension as critical if the anyExtendedKeyUsage
   KeyPurposeId is present.  Applications that require the presence of a
   particular purpose MAY reject certificates that include the
   anyExtendedKeyUsage OID but not the particular OID expected for the
   application.
'''
class ekuBadCritical(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.EXTENDED_KEY_USAGE)

    def Execute(self,c):
        try:
            if c.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).critical:
                for item in c.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value:
                    if item == ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE:
                        return  base.LintResult(base.LintStatus.Warn)
            return  base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("w_eku_critical_improperly","Conforming CAs SHOULD NOT mark extended key usage extension as critical if the anyExtendedKeyUsage KeyPurposedID is present","RFC 5280: 4.2.1.12",base.LintSource.RFC5280,Time.RFC3280Date,ekuBadCritical()))