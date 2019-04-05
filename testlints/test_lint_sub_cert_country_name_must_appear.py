import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_country_name_must_appear
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TesSubCertCountryNameMustAppear(unittest.TestCase):
    '''test lint_sub_cert_country_name_must_appear.py'''
    def test_SubCertCountryNameMustAppear(self):
        certPath ='..\\testCerts\\subCertCountryNameMustAppear.pem'
        lint_sub_cert_country_name_must_appear.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_country_name_must_appear"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)


if __name__=="__main__":
    unittest.main(verbosity=2)