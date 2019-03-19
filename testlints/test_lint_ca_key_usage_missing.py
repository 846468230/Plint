import sys
sys.path.append("..")
from lints import base
from lints import lint_ca_key_usage_missing
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCaKeyUsageMissing(unittest.TestCase):
    '''test lint_ca_key_usage_missing.py'''
    def test_CaKeyUsageMissing(self):
        certPath ='..\\testCerts\\caKeyUsageMissing.pem'
        lint_ca_key_usage_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ca_key_usage_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_KeyUsagePresent(self):
        certPath ='..\\testCerts\\caKeyUsageCrit.pem'
        lint_ca_key_usage_missing.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ca_key_usage_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)