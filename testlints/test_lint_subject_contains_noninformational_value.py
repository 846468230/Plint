import sys
sys.path.append("..")
from lints import base
from lints import lint_subject_contains_noninformational_value
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubjectNotInformational(unittest.TestCase):
    '''test lint_subject_contains_noninformational_value.py'''
    def test_SubjectNotInformational(self):
        certPath ='..\\testCerts\\illegalChar.pem'
        lint_subject_contains_noninformational_value.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_contains_noninformational_value"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubjectInformational(self):
        certPath ='..\\testCerts\\legalChar.pem'
        lint_subject_contains_noninformational_value.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_contains_noninformational_value"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)