import sys
sys.path.append("..")
from lints import base
from lints import lint_subject_multiple_rdn
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubjectRDNTwoAttribute(unittest.TestCase):
    '''test lint_subject_multiple_rdn.py'''
    def test_SubjectRDNTwoAttribute(self):
        certPath ='..\\testCerts\\subjectRDNTwoAttribute.pem'
        lint_subject_multiple_rdn.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["n_multiple_subject_rdn"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SubjectRDNOneAttribute(self):
        certPath ='..\\testCerts\\RSASHA1Good.pem'
        lint_subject_multiple_rdn.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["n_multiple_subject_rdn"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)