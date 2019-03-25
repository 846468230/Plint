import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_ian_dns_not_ia5_string
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestIANDNSIA5String(unittest.TestCase):
    '''test lint_ext_ian_dns_not_ia5_string.py'''
    def test_IANDNSIA5String(self):
        certPath ='..\\testCerts\\SANNoEntries.pem'
        lint_ext_ian_dns_not_ia5_string.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_ian_dns_not_ia5_string"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_IANDNSNotIA5String(self):
        certPath ='..\\testCerts\\IANDNSNotIA5String.pem'
        lint_ext_ian_dns_not_ia5_string.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_ian_dns_not_ia5_string"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
