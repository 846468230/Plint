import sys
sys.path.append("..")
from lints import base
from lints import lint_ca_subject_field_empty
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCaKeyUsageNotCrit(unittest.TestCase):
    '''test lint_ca_subject_field_empty.py'''
    def test_CaSubjectMissing(self):
        certPath ='..\\testCerts\\caSubjectMissing.pem'
        lint_ca_subject_field_empty.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ca_subject_field_empty"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_CaSubjectValid(self):
        certPath ='..\\testCerts\\caValCountry.pem'
        lint_ca_subject_field_empty.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ca_subject_field_empty"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)