import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_ian_space_dns_name
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestIANEmptyDNS(unittest.TestCase):
    '''test lint_ext_ian_space_dns_name.py'''
    def test_IANEmptyDNS(self):
        certPath ='..\\testCerts\\IANEmptyDNS.pem'
        lint_ext_ian_space_dns_name.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_ian_space_dns_name"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_IANNotEmptyDNS(self):
        certPath ='..\\testCerts\\SANNoEntries.pem'
        lint_ext_ian_space_dns_name.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_ian_space_dns_name"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
