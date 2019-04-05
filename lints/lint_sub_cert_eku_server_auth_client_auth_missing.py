from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,ExtendedKeyUsageOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.3
extKeyUsage (required)
Either the value id-kp-serverAuth [RFC5280] or id-kp-clientAuth [RFC5280] or both values MUST be present. id-kp-emailProtection [RFC5280] MAY be present. Other values SHOULD NOT be present.
'''
class subExtKeyUsageClientOrServer(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c) and ca.IsExtInCert(c,ExtensionOID.EXTENDED_KEY_USAGE)

    def Execute(self,c):
        try:
            extendedKeyUsages = c.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            for extendedKeyUsage in extendedKeyUsages:
                if extendedKeyUsage == ExtendedKeyUsageOID.SERVER_AUTH or extendedKeyUsage == ExtendedKeyUsageOID.CLIENT_AUTH :
                    return  base.LintResult(base.LintStatus.Pass)
            return  base.LintResult(base.LintStatus.Error) 
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Error)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_eku_server_auth_client_auth_missing","Subscriber certificates MUST have have either id-kp-serverAuth or id-kp-clientAuth or both present in extKeyUsage","BRs: 7.1.2.3",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subExtKeyUsageClientOrServer()))