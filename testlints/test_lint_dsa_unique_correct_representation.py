import sys
sys.path.append("..")
from lints import base
from lints import lint_dsa_unique_correct_representation
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDSAUniqueCorrectRepresentation(unittest.TestCase):
    '''test lint_dsa_unique_correct_representation.py'''
    def test_DSAUniqueCorrectRepresentation(self):
        certPath ='..\\testCerts\\dsaUniqueRep.pem'
        lint_dsa_unique_correct_representation.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dsa_unique_correct_representation"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        

if __name__=="__main__":
    unittest.main(verbosity=2)
