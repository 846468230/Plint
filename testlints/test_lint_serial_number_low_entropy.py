import sys
sys.path.append("..")
from lints import base
from lints import lint_serial_number_low_entropy
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSnLowEntropy(unittest.TestCase):
    '''test lint_serial_number_low_entropy.py'''
    def test_SnLowEntropy(self):
        certPath ='..\\testCerts\\serialNumberLowEntropy.pem'
        lint_serial_number_low_entropy.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_serial_number_low_entropy"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)