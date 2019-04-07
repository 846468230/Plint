import sys
sys.path.append("..")
from lints import base
from lints import lint_subject_given_name_max_length
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubjectGivenNameLengthOK(unittest.TestCase):
    '''test lint_subject_given_name_max_length.py'''
    def test_SubjectGivenNameLengthOK(self):
        certPath ='..\\testCerts\\subjectGivenName.pem'
        lint_subject_given_name_max_length.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_given_name_max_length"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SubjectGivenNameTooLong(self):
        certPath ='..\\testCerts\\subjectGivenNameToolLong.pem'
        lint_subject_given_name_max_length.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_given_name_max_length"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)