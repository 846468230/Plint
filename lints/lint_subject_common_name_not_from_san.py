from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,NameOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
BRs: 7.1.4.2.2
If present, this field MUST contain a single IP address
or Fully‐Qualified Domain Name that is one of the values
contained in the Certificate’s subjectAltName extension (see Section 7.1.4.2.1).
'''
class subjectCommonNameNotFromSAN(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return not ca.IsCACert(c) and c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)

    def Execute(self,c):
        try:
            commonname=[]
            for commonName in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                commonname.append(commonName.value.lower())
            sans = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for dns in sans.value.get_values_for_type(x509.DNSName):
                if dns.lower() in commonname:
                    return base.LintResult(base.LintStatus.Pass)
            
            for ip in sans.value.get_values_for_type(x509.IPAddress):
                if ip in commonname:
                    return base.LintResult(base.LintStatus.Pass)
            return base.LintResult(base.LintStatus.Error)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)


def init():
    base.RegisterLint(base.Lint("e_subject_common_name_not_from_san","The common name field in subscriber certificates must include only names from the SAN extension","BRs: 7.1.4.2.2",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subjectCommonNameNotFromSAN()))