import sys
sys.path.append("..")
from lints import base
from lints import lint_dsa_improper_modulus_or_divisor_size
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDSAImproperModulesOrDivisorSize(unittest.TestCase):
    '''test lint_dsa_improper_modulus_or_divisor_size.py'''
    def test_DSAImproperModulesOrDivisorSize(self):
        certPath ='..\\testCerts\\dsaNotShorterThan2048Bits.pem'
        lint_dsa_improper_modulus_or_divisor_size.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dsa_improper_modulus_or_divisor_size"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_DSANotImproperModulesOrDivisorSize(self):
        certPath ='..\\testCerts\\dsaShorterThan2048Bits.pem'
        lint_dsa_improper_modulus_or_divisor_size.init()
        
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dsa_improper_modulus_or_divisor_size"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
