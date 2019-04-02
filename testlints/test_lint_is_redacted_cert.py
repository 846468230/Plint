import sys
sys.path.append("..")
from lints import base
from lints import lint_is_redacted_cert
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDNSNameContainsQuestionMark(unittest.TestCase):
    '''test lint_is_redacted_cert.py'''
    def test_DNSNameContainsQuestionMark(self):
        certPath ='..\\testCerts\\dnsNameContainsQuestionMark.pem'
        lint_is_redacted_cert.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["n_contains_redacted_dnsname"].Execute(cert)
            self.assertEqual(base.LintStatus.Notice,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
