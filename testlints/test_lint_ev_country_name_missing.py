import sys
sys.path.append("..")
from lints import base
from lints import lint_ev_country_name_missing
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestEvHasCountry(unittest.TestCase):
    '''test lint_ev_country_name_missing.py'''
    def test_EvHasCountry(self):
        certPath ='..\\testCerts\\evAllGood.pem'
        lint_ev_country_name_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ev_country_name_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_EvNoCountry(self):
        certPath ='..\\testCerts\\evNoCountry.pem'
        lint_ev_country_name_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ev_country_name_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
