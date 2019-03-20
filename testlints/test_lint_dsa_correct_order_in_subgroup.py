import sys
sys.path.append("..")
from lints import base
from lints import lint_dsa_correct_order_in_subgroup
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDSACorrectOrderSubgroup(unittest.TestCase):
    '''test lint_dsa_correct_order_in_subgroup.py'''
    def test_DSACorrectOrderSubgroup(self):
        certPath ='..\\testCerts\\dsaCorrectOrderInSubgroup.pem'
        lint_dsa_correct_order_in_subgroup.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dsa_correct_order_in_subgroup"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
'''    def test_DSANotCorrectOrderSubgroup(self):
        certPath ='..\\testCerts\\dsaCorrectOrderInSubgroup.pem'
        lint_dsa_correct_order_in_subgroup.init()
        
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            dsakey = cert.public_key()
            Numbers = dsakey.public_numbers().parameter_numbers
            pMinusOne = Numbers.p-1
            cert.public_key().public_numbers().parameter_numbers.g=pMinusOne
            out = base.Lints["e_dsa_correct_order_in_subgroup"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
'''
if __name__=="__main__":
    unittest.main(verbosity=2)
