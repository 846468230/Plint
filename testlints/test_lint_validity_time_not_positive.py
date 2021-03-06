import sys
sys.path.append("..")
from lints import base
from lints import lint_validity_time_not_positive
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestValidityNegative(unittest.TestCase):
    '''test lint_validity_time_not_positive.py'''
    def test_ValidityNegative(self):
        certPath ='..\\testCerts\\validityNegative.pem'
        lint_validity_time_not_positive.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_validity_time_not_positive"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def testValidityPositive(self):
        certPath ='..\\testCerts\\IANURIValid.pem'
        lint_validity_time_not_positive.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_validity_time_not_positive"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)