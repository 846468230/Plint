import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_ca_crl_distribution_points_does_not_contain_url
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCaCrlNoUrl(unittest.TestCase):
    '''test lint_sub_ca_crl_distribution_points_does_not_contain_url.py'''
    def test_SubCaCrlNoUrl(self):
        certPath ='..\\testCerts\\subCaCrlMissing.pem'
        lint_sub_ca_crl_distribution_points_does_not_contain_url.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_ca_crl_distribution_points_does_not_contain_url"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubCaCrlUrlPresent(self):
        certPath ='..\\testCerts\\subCAWcrlDistNoCrit.pem'
        lint_sub_ca_crl_distribution_points_does_not_contain_url.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_ca_crl_distribution_points_does_not_contain_url"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)