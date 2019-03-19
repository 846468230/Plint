# -*- coding: utf-8 -*-
import sys
sys.path.append("..")
from lints import base
from lints import lint_ca_is_ca
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class test_KeyCertSignNotCA(unittest.TestCase):
    """Test lint_ca_is_ca.py"""
    def test_BasicConstNotCrit(self):
        """Test BasicConstNotCrit"""
        certPath ='..\\testCerts\\keyCertSignNotCA.pem'
        lint_ca_is_ca.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ca_is_ca"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
    
    def test_KeyCertSignCA(self):
        """Test lint_basic_constraints_critical.py"""
        certPath="..\\testCerts\\keyCertSignCA.pem"
        lint_ca_is_ca.init()
        with open(certPath,"rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(),default_backend())
            out=base.Lints["e_ca_is_ca"] .Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=='__main__':
    unittest.main(verbosity=2)