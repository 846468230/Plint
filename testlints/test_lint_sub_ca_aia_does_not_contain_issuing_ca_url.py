import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_ca_aia_does_not_contain_issuing_ca_url
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCaAiaNoIssuerUrl(unittest.TestCase):
    '''test lint_sub_ca_aia_does_not_contain_issuing_ca_url.py'''
    def test_SubCaAiaNoIssuerUrl(self):
        certPath ='..\\testCerts\\subCAWOcspURL.pem'
        lint_sub_ca_aia_does_not_contain_issuing_ca_url.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_sub_ca_aia_does_not_contain_issuing_ca_url"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_SubCaAiaHasIssuerUrl(self):
        certPath ='..\\testCerts\\subCAWBothURL.pem'
        lint_sub_ca_aia_does_not_contain_issuing_ca_url.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_sub_ca_aia_does_not_contain_issuing_ca_url"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)