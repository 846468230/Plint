import sys
sys.path.append("..")
from lints import base
from lints import lint_subject_country_not_iso
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCountryNotIso(unittest.TestCase):
    '''test lint_subject_country_not_iso.py'''
    def test_CountryNotIso(self):
        certPath ='..\\testCerts\\subjectInvalidCountry.pem'
        lint_subject_country_not_iso.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_country_not_iso"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_CountryIsIso(self):
        certPath ='..\\testCerts\\subjectValidCountry.pem'
        lint_subject_country_not_iso.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_country_not_iso"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)