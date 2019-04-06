import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_sha1_expiration_too_long
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestRsaSha1TooLong(unittest.TestCase):
    '''test lint_sub_cert_sha1_expiration_too_long.py'''
    def test_RsaSha1TooLong(self):
        certPath ='..\\testCerts\\sha1ExpireAfter2017.pem'
        lint_sub_cert_sha1_expiration_too_long.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_sub_cert_sha1_expiration_too_long"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_RsaSha1NotTooLong(self):
        certPath ='..\\testCerts\\sha1ExpirePrior2017.pem'
        lint_sub_cert_sha1_expiration_too_long.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_sub_cert_sha1_expiration_too_long"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)