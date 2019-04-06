import sys
sys.path.append("..")
from lints import base
from lints import lint_subject_common_name_included
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCN(unittest.TestCase):
    '''test lint_subject_common_name_included.py'''
    def test_CN(self):
        certPath ='..\\testCerts\\commonNamesURL.pem'
        lint_subject_common_name_included.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["n_subject_common_name_included"].Execute(cert)
            self.assertEqual(base.LintStatus.Notice,out.Status)

    def test_SubCertValidTimeGood(self):
        certPath ='..\\testCerts\\commonNamesGood.pem'
        lint_subject_common_name_included.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["n_subject_common_name_included"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)