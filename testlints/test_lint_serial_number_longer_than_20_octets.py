import sys
sys.path.append("..")
from lints import base
from lints import lint_serial_number_longer_than_20_octets
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSnTooLarge(unittest.TestCase):
    '''test lint_serial_number_longer_than_20_octets.py'''
    def test_SnTooLarge(self):
        certPath ='..\\testCerts\\serialNumberLarge.pem'
        lint_serial_number_longer_than_20_octets.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_serial_number_longer_than_20_octets"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SnNotTooLarge(self):
        certPath ='..\\testCerts\\serialNumberValid.pem'
        lint_serial_number_longer_than_20_octets.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_serial_number_longer_than_20_octets"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)