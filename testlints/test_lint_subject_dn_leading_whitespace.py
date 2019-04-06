import sys
sys.path.append("..")
from lints import base
from lints import lint_subject_dn_leading_whitespace
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubjectDNLeadingSpace(unittest.TestCase):
    '''test lint_subject_dn_leading_whitespace.py'''
    def test_SubjectDNLeadingSpace(self):
        certPath ='..\\testCerts\\subjectDNLeadingSpace.pem'
        lint_subject_dn_leading_whitespace.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_subject_dn_leading_whitespace"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_SubjectDNGood(self):
        certPath ='..\\testCerts\\domainValGoodSubject.pem'
        lint_subject_dn_leading_whitespace.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_subject_dn_leading_whitespace"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)