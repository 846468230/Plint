import sys
sys.path.append("..")
from lints import base
from lints import lint_root_ca_key_usage_must_be_critical
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestRootCAKeyUsageCritical(unittest.TestCase):
    '''test lint_root_ca_key_usage_must_be_critical.py'''
    def test_RootCAEKU(self):
        certPath ='..\\testCerts\\rootCAKeyUsagePresent.pem'
        lint_root_ca_key_usage_must_be_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_root_ca_key_usage_must_be_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_RootCAKeyUsageNotCritical(self):
        certPath ='..\\testCerts\\rootCAKeyUsageNotCritical.pem'
        lint_root_ca_key_usage_must_be_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_root_ca_key_usage_must_be_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)