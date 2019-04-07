import sys
sys.path.append("..")
from lints import base
from lints import lint_subject_empty_without_san
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubEmptyNoSAN(unittest.TestCase):
    '''test lint_subject_empty_without_san.py'''
    def test_SubEmptyNoSAN(self):
        certPath ='..\\testCerts\\subjectEmptyNoSAN.pem'
        lint_subject_empty_without_san.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_empty_without_san"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubEmptyYesSAN(self):
        certPath ='..\\testCerts\\SANSubjectEmptyNotCritical.pem'
        lint_subject_empty_without_san.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_empty_without_san"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)