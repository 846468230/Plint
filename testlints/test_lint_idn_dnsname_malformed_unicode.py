import sys
sys.path.append("..")
from lints import base
from lints import lint_idn_dnsname_malformed_unicode
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestIDNMalformedUnicode(unittest.TestCase):
    '''test lint_idn_dnsname_malformed_unicode.py'''
    def test_IDNMalformedUnicode(self):
        certPath ='..\\testCerts\\idnMalformedUnicode.pem'
        lint_idn_dnsname_malformed_unicode.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_international_dns_name_not_unicode"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_IDNCorrectUnicode(self):
        certPath ='..\\testCerts\\idnCorrectUnicode.pem'
        lint_idn_dnsname_malformed_unicode.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_international_dns_name_not_unicode"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
