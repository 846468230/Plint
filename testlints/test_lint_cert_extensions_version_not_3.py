import sys
sys.path.append("..")
from lints import base
from lints import lint_cert_extensions_version_not_3
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestExtsV2(unittest.TestCase):
    '''test lint_cert_extensions_version_not_3.py'''
    def test_ExtsV2(self):
        certPath ='..\\testCerts\\certVersion2WithExtension.pem'
        lint_cert_extensions_version_not_3.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_cert_extensions_version_not_3"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_ExtsV3(self):
        certPath ='..\\testCerts\\caBasicConstCrit.pem'
        lint_cert_extensions_version_not_3.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_cert_extensions_version_not_3"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_ExtsV2Pass(self):
        certPath ='..\\testCerts\\certVersion2NoExtensions.pem'
        lint_cert_extensions_version_not_3.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_cert_extensions_version_not_3"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
if __name__=="__main__":
    unittest.main(verbosity=2)