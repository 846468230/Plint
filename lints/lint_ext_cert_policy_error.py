from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,oid,ev
from datetime import timedelta


class ExtCertPolicyError(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.CERTIFICATE_POLICIES)
    
    def Execute(self,c):
        try:
            certpolicies = c.extensions.get_extension_for_class(x509.CertificatePolicies).value
            return  base.LintResult(base.LintStatus.Pass)
        except ValueError as e:
            if str(e) =="The <ObjectIdentifier(oid=2.5.29.32, name=certificatePolicies)> extension is invalid and can't be parsed":
                return base.LintResult(base.LintStatus.Error)
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("e_ext_cert_policy_valid","A certificate can't be parsed error","RFC 5280",base.LintSource.RFC5280,Time.RFC5280Date,ExtCertPolicyError()))