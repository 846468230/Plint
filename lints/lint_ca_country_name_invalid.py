from lints import base
from util import ca
from cryptography.x509.oid import NameOID
from util.time import Time
from util.countries import IsISOCountryCode
'''
BRs: 7.1.2.1e
The	Certificate	Subject	MUST contain the following:
‐	countryName	(OID 2.5.4.6).
This field MUST	contain	the	two‐letter	ISO	3166‐1 country code	for	the country
in which the CA’s place	of business	is located.
'''
class caCountryNameInvalid(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsCACert(c)
    
    def Execute(self,c):
        try:
            countrys=c.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
            for country in countrys:
                if not IsISOCountryCode(country.value):
                    return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)  
        except ValueError:
            return base.LintResult(base.LintStatus.NA)  

def init():
    base.RegisterLint(base.Lint("e_ca_country_name_invalid","Root and Subordinate CA certificates MUST have a two-letter country code specified in ISO 3166-1","BRs: 7.1.2.1",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,caCountryNameInvalid()))