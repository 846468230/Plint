import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_subject_key_identifier_missing_ca
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCaSkiMissing(unittest.TestCase):
    '''test lint_ext_subject_key_identifier_missing_ca.py'''
    def test_SubCaSkiMissing(self):
        certPath ='..\\testCerts\\subCANoSKI.pem'
        lint_ext_subject_key_identifier_missing_ca.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_subject_key_identifier_missing_ca"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubCaSkiPresent(self):
        certPath ='..\\testCerts\\skiNotCriticalCA.pem'
        lint_ext_subject_key_identifier_missing_ca.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_subject_key_identifier_missing_ca"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
