import sys
sys.path.append("..")
from lints import base
from lints import lint_dnsname_wildcard_only_in_left_label
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDNSNameWildcardOnlyInLeftLabel(unittest.TestCase):
    '''test lint_dnsname_wildcard_only_in_left_label.py'''
    def test_DNSNameWildcardOnlyInLeftLabel(self):
        certPath ='..\\testCerts\\dnsNameWildcardOnlyInLeftLabel.pem'
        lint_dnsname_wildcard_only_in_left_label.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_wildcard_only_in_left_label"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_WildcardNotLeftOfPublicSuffix(self):
        certPath ='..\\testCerts\\dnsNameWildcardNotOnlyInLeftLabel.pem'
        lint_dnsname_wildcard_only_in_left_label.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_wildcard_only_in_left_label"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
