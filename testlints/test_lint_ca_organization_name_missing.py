import sys
sys.path.append("..")
from lints import base
from lints import lint_ca_organization_name_missing
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCAOrgNameMissing(unittest.TestCase):
    '''test lint_ca_organization_name_missing.py'''
    def test_CAOrgNameBlank(self):
        certPath ='..\\testCerts\\caOrgNameEmpty.pem'
        lint_ca_organization_name_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ca_organization_name_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_CAOrgNameMissing(self):
        certPath ='..\\testCerts\\caOrgNameMissing.pem'
        lint_ca_organization_name_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ca_organization_name_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_CAOrgNameValid(self):
        certPath ='..\\testCerts\\caValCountry.pem'
        lint_ca_organization_name_missing.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ca_organization_name_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)