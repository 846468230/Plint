import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_valid_time_longer_than_39_months
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCertValidTimeLongerThan39Months(unittest.TestCase):
    '''test lint_sub_cert_valid_time_longer_than_39_months.py'''
    def test_SubCertValidTimeLongerThan39Months(self):
        certPath ='..\\testCerts\\subCertValidTimeTooLong.pem'
        lint_sub_cert_valid_time_longer_than_39_months.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_valid_time_longer_than_39_months"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubCertValidTimeGood(self):
        certPath ='..\\testCerts\\subCertValidTimeGood.pem'
        lint_sub_cert_valid_time_longer_than_39_months.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_valid_time_longer_than_39_months"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)