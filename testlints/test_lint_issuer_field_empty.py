import sys
sys.path.append("..")
from lints import base
from lints import lint_issuer_field_empty
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestNoIssuerField(unittest.TestCase):
    '''test lint_issuer_field_empty.py'''
    def test_NoIssuerField(self):
        certPath ='..\\testCerts\\issuerFieldMissing.pem'
        lint_issuer_field_empty.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_issuer_field_empty"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def testHasIssuerField(self):
        certPath ='..\\testCerts\\issuerFieldFilled.pem'
        lint_issuer_field_empty.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_issuer_field_empty"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
