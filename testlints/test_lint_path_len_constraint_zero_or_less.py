import sys
sys.path.append("..")
from lints import base
from lints import lint_path_len_constraint_zero_or_less
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCaMaxLenNegative(unittest.TestCase):
    '''test lint_path_len_constraint_zero_or_less.py'''
    def test_CaMaxLenNegative(self):
        certPath ='..\\testCerts\\caMaxPathNegative.pem'
        lint_path_len_constraint_zero_or_less.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_path_len_constraint_zero_or_less"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubCerMaxLenNegative(self):
        certPath ='..\\testCerts\\subCertPathLenNegative.pem'
        lint_path_len_constraint_zero_or_less.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_path_len_constraint_zero_or_less"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
    
    def test_CaMaxLenPositive(self):
        certPath ='..\\testCerts\\caMaxPathLenPositive.pem'
        lint_path_len_constraint_zero_or_less.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_path_len_constraint_zero_or_less"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SubCertMaxLenPositive(self):
        certPath ='..\\testCerts\\subCertPathLenPositive.pem'
        lint_path_len_constraint_zero_or_less.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_path_len_constraint_zero_or_less"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SubCertMaxLenMissing(self):
        certPath ='..\\testCerts\\caBasicConstMissing.pem'
        lint_path_len_constraint_zero_or_less.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_path_len_constraint_zero_or_less"].Execute(cert)
            self.assertEqual(base.LintStatus.NA,out.Status)

    def test_CAMaxLenNone(self):
        certPath ='..\\testCerts\\caMaxPathLenMissing.pem'
        lint_path_len_constraint_zero_or_less.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_path_len_constraint_zero_or_less"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
