import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_subject_key_identifier_missing_sub_cert
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCertSkiMissing(unittest.TestCase):
    '''test lint_ext_subject_key_identifier_missing_sub_cert.py'''
    def test_SubCertSkiMissing(self):
        certPath ='..\\testCerts\\subCertNoSKI.pem'
        lint_ext_subject_key_identifier_missing_sub_cert.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_subject_key_identifier_missing_sub_cert"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_SubCertSkiPresent(self):
        certPath ='..\\testCerts\\orgValGoodAllFields.pem'
        lint_ext_subject_key_identifier_missing_sub_cert.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_subject_key_identifier_missing_sub_cert"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
