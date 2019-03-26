import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_name_constraints_not_in_ca
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestNameConstraintsNotInCa(unittest.TestCase):
    '''test lint_ext_name_constraints_not_in_ca.py'''
    def test_NameConstraintsNotInCa(self):
        certPath ='..\\testCerts\\noNameConstraint.pem'
        lint_ext_name_constraints_not_in_ca.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_name_constraints_not_in_ca"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_NameConstraintsInCa(self):
        certPath ='..\\testCerts\\subCAWNameConstCrit.pem'
        lint_ext_name_constraints_not_in_ca.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_name_constraints_not_in_ca"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
