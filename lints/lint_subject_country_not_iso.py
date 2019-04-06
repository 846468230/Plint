from lints import base
from util import ca
from cryptography.x509.oid import NameOID
from util.time import Time
from util.countries import IsISOCountryCode
'''
BRs: 7.1.4.2.2
Certificate Field: issuer:countryName (OID 2.5.4.6)
Required/Optional: Required
Contents: This field MUST contain the two-letter ISO 3166-1 country code for the country in which the issuer’s
place of business is located.
'''
class countryNotIso(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return True
    
    def Execute(self,c):
        try:
            countrys=c.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
            for country in countrys:
                if not IsISOCountryCode(country.value):
                    return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)  
        except ValueError as e:
            if str(e) == "Country name must be a 2 character country code":
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.NA)  

def init():
    base.RegisterLint(base.Lint("e_subject_country_not_iso","The country name field MUST contain the two-letter ISO code for the country or XX","BRs: 7.1.4.2.2",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,countryNotIso()))