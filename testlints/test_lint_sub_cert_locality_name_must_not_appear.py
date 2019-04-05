import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_locality_name_must_not_appear
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCertLocalityNameProhibited(unittest.TestCase):
    '''test lint_sub_cert_locality_name_must_not_appear.py'''
    def test_SubCertLocalityNameProhibited(self):
        certPath ='..\\testCerts\\subCertLocalityNameProhibited.pem'
        lint_sub_cert_locality_name_must_not_appear.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_locality_name_must_not_appear"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubCertLocalityNameNotProhibited(self):
        certPath ='..\\testCerts\\subCertLocalityNameNotProhibited.pem'
        lint_sub_cert_locality_name_must_not_appear.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_locality_name_must_not_appear"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)