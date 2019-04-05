import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_postal_code_prohibited
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCertPostalCodeProhibited(unittest.TestCase):
    '''test lint_sub_cert_postal_code_prohibited.py'''
    def test_SubCertPostalCodeProhibited(self):
        certPath ='..\\testCerts\\subCertProvinceMustNotAppear.pem'
        lint_sub_cert_postal_code_prohibited.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_postal_code_must_not_appear"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubCertPostalCodeNotProhibited(self):
        certPath ='..\\testCerts\\subCertPostalCodeNotProhibited.pem'
        lint_sub_cert_postal_code_prohibited.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_postal_code_must_not_appear"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)