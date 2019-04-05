import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_or_sub_ca_using_sha1
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSHA1After2016(unittest.TestCase):
    '''test lint_sub_cert_or_sub_ca_using_sha1.py'''
    def test_SHA1After2016(self):
        certPath ='..\\testCerts\\rsawithsha1after2016.pem'
        lint_sub_cert_or_sub_ca_using_sha1.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_or_sub_ca_using_sha1"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SHA1Before2016(self):
        certPath ='..\\testCerts\\rsawithsha1before2016.pem'
        lint_sub_cert_or_sub_ca_using_sha1.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_or_sub_ca_using_sha1"].Execute(cert)
            self.assertEqual(base.LintStatus.NE,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)