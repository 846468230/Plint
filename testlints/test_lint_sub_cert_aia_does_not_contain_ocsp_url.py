import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_aia_does_not_contain_ocsp_url
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCertNoIssuerOcsp(unittest.TestCase):
    '''test lint_sub_cert_aia_does_not_contain_ocsp_url.py'''
    def test_SubCertNoIssuerOcsp(self):
        certPath ='..\\testCerts\\subCertWIssuerURL.pem'
        lint_sub_cert_aia_does_not_contain_ocsp_url.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_aia_does_not_contain_ocsp_url"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubCertHasIssuerOcsp(self):
        certPath ='..\\testCerts\\subCertWOcspURL.pem'
        lint_sub_cert_aia_does_not_contain_ocsp_url.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_aia_does_not_contain_ocsp_url"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)