import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_is_ca
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCertIsNotCA(unittest.TestCase):
    '''test lint_sub_cert_is_ca.py'''
    def test_SubCertIsNotCA(self):
        certPath ='..\\testCerts\\subCertIsNotCA.pem'
        lint_sub_cert_is_ca.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_not_is_ca"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_EkuNeitherPres(self):
        certPath ='..\\testCerts\\subCertIsCA.pem'
        lint_sub_cert_is_ca.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_not_is_ca"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)