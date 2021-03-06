import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_san_uri_relative
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSANURIRelative(unittest.TestCase):
    '''test lint_ext_san_uri_relative.py'''
    def test_SANURIRelative(self):
        certPath ='..\\testCerts\\SANURIRelative.pem'
        lint_ext_san_uri_relative.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_uri_relative"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SANURIAbsolute(self):
        certPath ='..\\testCerts\\SANURIAbsolute.pem'
        lint_ext_san_uri_relative.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_uri_relative"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
