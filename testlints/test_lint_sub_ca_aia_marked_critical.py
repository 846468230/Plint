import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_ca_aia_marked_critical
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCAAIAMarkedCritical(unittest.TestCase):
    '''test lint_sub_ca_aia_marked_critical.py'''
    def test_SubCAAIAMarkedCritical(self):
        certPath ='..\\testCerts\\subCAAIAMarkedCritical.pem'
        lint_sub_ca_aia_marked_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_ca_aia_marked_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubCAAIANotMarkedCritical(self):
        certPath ='..\\testCerts\\subCAAIANotMarkedCritical.pem'
        lint_sub_ca_aia_marked_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_ca_aia_marked_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)