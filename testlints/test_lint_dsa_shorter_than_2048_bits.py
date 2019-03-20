import sys
sys.path.append("..")
from lints import base
from lints import lint_dsa_shorter_than_2048_bits
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDSAShorterThan2048Bits(unittest.TestCase):
    '''test lint_dsa_shorter_than_2048_bits.py'''
    def test_DSAShorterThan2048Bits(self):
        certPath ='..\\testCerts\\dsaShorterThan2048Bits.pem'
        lint_dsa_shorter_than_2048_bits.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dsa_shorter_than_2048_bits"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_DSANotShorterThan2048Bits(self):
        certPath ='..\\testCerts\\dsaNotShorterThan2048Bits.pem'
        lint_dsa_shorter_than_2048_bits.init()
        
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dsa_shorter_than_2048_bits"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
