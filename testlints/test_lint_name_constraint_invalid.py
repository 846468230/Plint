import sys
sys.path.append("..")
from lints import base
from lints import lint_name_constraint_invalid
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TesNameConstraintInvalid(unittest.TestCase):
    '''test lint_name_constraint_invalid.py'''
    def test_NcMinNotZero(self):
        certPath ='..\\testCerts\\ncMinZero.pem'
        lint_name_constraint_invalid.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_name_constraint_Invalid"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def testNcNoEDI(self):
        certPath ='..\\testCerts\\ncOnEDI.pem'
        lint_name_constraint_invalid.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_name_constraint_Invalid"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
    
    def testHasNameConstraint(self):
        certPath ='..\\testCerts\\ncOnX400.pem'
        lint_name_constraint_invalid.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_name_constraint_Invalid"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
