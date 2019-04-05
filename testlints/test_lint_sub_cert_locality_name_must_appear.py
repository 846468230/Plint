import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_locality_name_must_appear
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCertLocalityNameMustAppear(unittest.TestCase):
    '''test lint_sub_cert_locality_name_must_appear.py'''
    def test_SubCertLocalityNameMustAppear(self):
        certPath ='..\\testCerts\\subCertLocalityNameMustAppear.pem'
        lint_sub_cert_locality_name_must_appear.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_locality_name_must_appear"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubCertLocalityNameDoesNotNeedToAppear(self):
        certPath ='..\\testCerts\\subCertLocalityNameDoesNotNeedToAppear.pem'
        lint_sub_cert_locality_name_must_appear.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_locality_name_must_appear"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)