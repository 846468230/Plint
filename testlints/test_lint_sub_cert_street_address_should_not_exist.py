import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_street_address_should_not_exist
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestStreetAddressShouldNotExist(unittest.TestCase):
    '''test lint_sub_cert_street_address_should_not_exist.py'''
    def test_StreetAddressShouldNotExist(self):
        certPath ='..\\testCerts\\streetAddressCannotExist.pem'
        lint_sub_cert_street_address_should_not_exist.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_street_address_should_not_exist"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_StreetAddressCanExist(self):
        certPath ='..\\testCerts\\streetAddressCanExist.pem'
        lint_sub_cert_street_address_should_not_exist.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_street_address_should_not_exist"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)