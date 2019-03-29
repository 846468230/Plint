import sys
sys.path.append("..")
from lints import base
from lints import lint_invalid_certificate_version
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCertVersion2(unittest.TestCase):
    '''test lint_invalid_certificate_version.py'''
    def test_CertVersion2(self):
        certPath ='..\\testCerts\\certVersion2WithExtension.pem'
        lint_invalid_certificate_version.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_invalid_certificate_version"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_CertVersion3(self):
        certPath ='..\\testCerts\\certVersion3NoExtensions.pem'
        lint_invalid_certificate_version.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_invalid_certificate_version"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
