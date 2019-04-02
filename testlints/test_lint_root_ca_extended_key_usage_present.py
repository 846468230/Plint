import sys
sys.path.append("..")
from lints import base
from lints import lint_root_ca_extended_key_usage_present
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestRootCAEKU(unittest.TestCase):
    '''test lint_root_ca_extended_key_usage_present.py'''
    def test_RootCAEKU(self):
        certPath ='..\\testCerts\\rootCAWithEKU.pem'
        lint_root_ca_extended_key_usage_present.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_root_ca_extended_key_usage_present"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_RootCANoEKU(self):
        certPath ='..\\testCerts\\rootCAValid.pem'
        lint_root_ca_extended_key_usage_present.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_root_ca_extended_key_usage_present"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)