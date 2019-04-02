import sys
sys.path.append("..")
from lints import base
from lints import lint_path_len_constraint_improperly_included
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCaMaxLenPresentNoCertSign(unittest.TestCase):
    '''test lint_path_len_constraint_improperly_included.py'''
    def test_CaMaxLenPresentNoCertSign(self):
        certPath ='..\\testCerts\\caMaxPathLenPresentNoCertSign.pem'
        lint_path_len_constraint_improperly_included.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_path_len_constraint_improperly_included"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_CaMaxLenPresentGood(self):
        certPath ='..\\testCerts\\caMaxPathLenPositive.pem'
        lint_path_len_constraint_improperly_included.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_path_len_constraint_improperly_included"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
    
    def test_CaMaxLenMissing(self):
        certPath ='..\\testCerts\\caMaxPathLenMissing.pem'
        lint_path_len_constraint_improperly_included.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_path_len_constraint_improperly_included"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SubCertMaxLenPresent(self):
        certPath ='..\\testCerts\\subCertPathLenPositive.pem'
        lint_path_len_constraint_improperly_included.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_path_len_constraint_improperly_included"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubCertMaxLenNone(self):
        certPath ='..\\testCerts\\orgValGoodAllFields.pem'
        lint_path_len_constraint_improperly_included.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_path_len_constraint_improperly_included"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
