import sys
sys.path.append("..")
from lints import base
from lints import lint_dnsname_contains_empty_label
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDNSNameEmptyLabel(unittest.TestCase):
    '''test lint_dnsname_contains_empty_label.py'''
    def test_DNSNameEmptyLabel(self):
        certPath ='..\\testCerts\\dnsNameEmptyLabel.pem'
        lint_dnsname_contains_empty_label.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_empty_label"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_DNSNameNotEmptyLabel(self):
        certPath ='..\\testCerts\\dnsNameNotEmptyLabel.pem'
        lint_dnsname_contains_empty_label.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_empty_label"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
