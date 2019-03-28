import sys
sys.path.append("..")
from lints import base
from lints import lint_ian_iana_pub_suffix_empty
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestIANBarePubSuffix(unittest.TestCase):
    '''test lint_ian_iana_pub_suffix_empty.py'''
    def test_IANBarePubSuffix(self):
        certPath ='..\\testCerts\\IANCritical.pem'
        lint_ian_iana_pub_suffix_empty.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ian_iana_pub_suffix_empty"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_IANGoodPubSuffix(self):
        certPath ='..\\testCerts\\IANGoodSuffix.pem'
        lint_ian_iana_pub_suffix_empty.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ian_iana_pub_suffix_empty"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
