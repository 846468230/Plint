import sys
sys.path.append("..")
from lints import base
from lints import lint_root_ca_contains_cert_policy
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestRootCACertPolicy(unittest.TestCase):
    '''test lint_root_ca_contains_cert_policy.py'''
    def test_RootCaMaxLenPresent(self):
        certPath ='..\\testCerts\\rootCAWithCertPolicy.pem'
        lint_root_ca_contains_cert_policy.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_root_ca_contains_cert_policy"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_RootCANoCertPolicy(self):
        certPath ='..\\testCerts\\rootCAValid.pem'
        lint_root_ca_contains_cert_policy.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_root_ca_contains_cert_policy"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)