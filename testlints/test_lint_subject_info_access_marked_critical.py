import sys
sys.path.append("..")
from lints import base
from lints import lint_subject_info_access_marked_critical
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSiaCrit(unittest.TestCase):
    '''test lint_subject_info_access_marked_critical.py'''
    def test_SiaCrit(self):
        certPath ='..\\testCerts\\siaCrit.pem'
        lint_subject_info_access_marked_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_info_access_marked_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SiaNotCrit(self):
        certPath ='..\\testCerts\\siaNotCrit.pem'
        lint_subject_info_access_marked_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_info_access_marked_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)