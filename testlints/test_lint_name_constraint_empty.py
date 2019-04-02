import sys
sys.path.append("..")
from lints import base
from lints import lint_name_constraint_empty
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestNoNameConstraint(unittest.TestCase):
    '''test lint_name_constraint_empty.py'''
    def test_NoNameConstraint(self):
        certPath ='..\\testCerts\\noNameConstraint.pem'
        lint_name_constraint_empty.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_name_constraint_empty"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def testHasNameConstraint(self):
        certPath ='..\\testCerts\\yesNameConstraint.pem'
        lint_name_constraint_empty.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_name_constraint_empty"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
