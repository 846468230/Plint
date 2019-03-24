from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,oid,ev
from datetime import timedelta
'''
The certificate policies extension contains a sequence of one or more
  policy information terms, each of which consists of an object identifier
  (OID) and optional qualifiers. Optional qualifiers, which MAY be present,
  are not expected to change the definition of the policy. A certificate
  policy OID MUST NOT appear more than once in a certificate policies extension.
'''

class ExtCertPolicyDuplicate(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.CERTIFICATE_POLICIES)
    
    def Execute(self,c):
        try:
            certpolicies = c.extensions.get_extension_for_class(x509.CertificatePolicies).value
            for i in range(len(certpolicies)):
                for j in range(i+1,len(certpolicies)):
                    if certpolicies[i].policy_identifier==certpolicies[j].policy_identifier:
                        return  base.LintResult(base.LintStatus.Error)

            return  base.LintResult(base.LintStatus.Pass)
        except ValueError as e:
            if str(e) =="The <ObjectIdentifier(oid=2.5.29.32, name=certificatePolicies)> extension is invalid and can't be parsed":
                return base.LintResult(base.LintStatus.Error)
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("e_ext_cert_policy_duplicate","A certificate policy OID must not appear more than once in the extension","RFC 5280: 4.2.1.4",base.LintSource.RFC5280,Time.RFC5280Date,ExtCertPolicyDuplicate()))