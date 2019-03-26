import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_policy_constraints_empty
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestPolicyConstraintsEmpty(unittest.TestCase):
    '''test lint_ext_policy_constraints_empty.py'''
    def test_PolicyConstraintsEmpty(self):
        certPath ='..\\testCerts\\policyConstEmpty.pem'
        lint_ext_policy_constraints_empty.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_policy_constraints_empty"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_PolicyConstraintsNotEmpty(self):
        certPath ='..\\testCerts\\policyConstGoodBoth.pem'
        lint_ext_policy_constraints_empty.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_policy_constraints_empty"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
