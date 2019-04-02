import sys
sys.path.append("..")
from lints import base
from lints import lint_root_ca_basic_constraints_path_len_constraint_field_present
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestRootCaMaxLenPresent(unittest.TestCase):
    '''test lint_root_ca_basic_constraints_path_len_constraint_field_present.py'''
    def test_RootCaMaxLenPresent(self):
        certPath ='..\\testCerts\\rootCaMaxPathLenPresent.pem'
        lint_root_ca_basic_constraints_path_len_constraint_field_present.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_root_ca_basic_constraints_path_len_constraint_field_present"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_RootCaMaxLenMissing(self):
        certPath ='..\\testCerts\\rootCaMaxPathLenMissing.pem'
        lint_root_ca_basic_constraints_path_len_constraint_field_present.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_root_ca_basic_constraints_path_len_constraint_field_present"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)