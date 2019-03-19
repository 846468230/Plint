# -*- coding: utf-8 -*-
import sys
sys.path.append("..")
from lints import base
from lints import lint_basic_constraints_not_critical
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class test_lint_basic_constraints_not_critical(unittest.TestCase):
    """Test lint_basic_constraints_not_critical.py"""
    def test_BasicConstNotCrit(self):
        """Test BasicConstNotCrit"""
        certPath ='..\\testCerts\\caBasicConstNotCrit.pem'
        lint_basic_constraints_not_critical.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_basic_constraints_not_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
    
    def test_BasicConstCrit(self):
        """Test lint_basic_constraints_critical.py"""
        certPath="..\\testCerts\\caBasicConstCrit.pem"
        lint_basic_constraints_not_critical.init()
        with open(certPath,"rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(),default_backend())
            out=base.Lints["e_basic_constraints_not_critical"] .Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=='__main__':
    unittest.main(verbosity=2)