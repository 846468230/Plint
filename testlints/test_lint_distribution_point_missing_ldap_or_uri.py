import sys
sys.path.append("..")
from lints import base
from lints import lint_distribution_point_missing_ldap_or_uri
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCRLDistNoHttp(unittest.TestCase):
    '''test lint_distribution_point_missing_ldap_or_uri.py'''
    def test_CRLDistNoHttp(self):
        certPath ='..\\testCerts\\crlDistribNoHTTP.pem'
        lint_distribution_point_missing_ldap_or_uri.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_distribution_point_missing_ldap_or_uri"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)
        
    def test_crlCRLDistHttp(self):
        certPath ='..\\testCerts\\crlDistribWithHTTP.pem'
        lint_distribution_point_missing_ldap_or_uri.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_distribution_point_missing_ldap_or_uri"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_CRLDistLdap(self):
        certPath ='..\\testCerts\\crlDistribWithLDAP.pem'
        lint_distribution_point_missing_ldap_or_uri.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_distribution_point_missing_ldap_or_uri"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
