import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_valid_time_longer_than_825_days
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCertValidTimeLongerThan825Days(unittest.TestCase):
    '''test lint_sub_cert_valid_time_longer_than_825_days.py'''
    def test_SubCertValidTimeLongerThan825Days(self):
        certPath ='..\\testCerts\\subCertOver825DaysBad.pem'
        lint_sub_cert_valid_time_longer_than_825_days.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_valid_time_longer_than_825_days"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubCertValidTimeLongerThan825DaysBeforeCutoff(self):
        certPath ='..\\testCerts\\subCertOver825DaysOK.pem'
        lint_sub_cert_valid_time_longer_than_825_days.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_valid_time_longer_than_825_days"].Execute(cert)
            self.assertEqual(base.LintStatus.NE,out.Status)
    
    def test_SubCertValidTime825Days(self):
        certPath ='..\\testCerts\\subCert825DaysOK.pem'
        lint_sub_cert_valid_time_longer_than_825_days.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_valid_time_longer_than_825_days"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)