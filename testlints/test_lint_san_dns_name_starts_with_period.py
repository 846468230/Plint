import sys
sys.path.append("..")
from lints import base
from lints import lint_san_dns_name_starts_with_period
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestBrSANDNSStartsWithPeriod(unittest.TestCase):
    '''test lint_san_dns_name_starts_with_period.py'''
    def test_BrSANDNSStartsWithPeriod(self):
        certPath ='..\\testCerts\\SANDNSPeriod.pem'
        lint_san_dns_name_starts_with_period.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_san_dns_name_starts_with_period"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_BrSANDNSNotPeriod(self):
        certPath ='..\\testCerts\\SANURIValid.pem'
        lint_san_dns_name_starts_with_period.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_san_dns_name_starts_with_period"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)