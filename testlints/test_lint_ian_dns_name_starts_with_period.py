import sys
sys.path.append("..")
from lints import base
from lints import lint_ian_dns_name_starts_with_period
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestBrIANDNSStartsWithPeriod(unittest.TestCase):
    '''test lint_ian_dns_name_starts_with_period.py'''
    def test_BrIANDNSStartsWithPeriod(self):
        certPath ='..\\testCerts\\IANDNSPeriod.pem'
        lint_ian_dns_name_starts_with_period.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ian_dns_name_starts_with_period"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_BrIANDNSNotPeriod(self):
        certPath ='..\\testCerts\\IANCritical.pem'
        lint_ian_dns_name_starts_with_period.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ian_dns_name_starts_with_period"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
