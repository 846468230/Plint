import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_eku_missing
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestEkuMissing(unittest.TestCase):
    '''test lint_sub_cert_eku_missing.py'''
    def test_EkuMissing(self):
        certPath ='..\\testCerts\\subExtKeyUsageMissing.pem'
        lint_sub_cert_eku_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_eku_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_EkuPresent(self):
        certPath ='..\\testCerts\\subExtKeyUsageServClient.pem'
        lint_sub_cert_eku_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_eku_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)