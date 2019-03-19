import sys
sys.path.append("..")
from lints import base
from lints import lint_dh_params_missing
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCertDHParamsMissing(unittest.TestCase):
    '''test lint_dh_params_missing.py'''
    def test_CertDHParamsMissing(self):
        certPath ='..\\testCerts\\dsaCorrectOrderInSubgroup.pem'
        lint_dh_params_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dsa_params_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    '''def test_CertDHParamsNotMissing(self):
        certPath ='..\\testCerts\\orgValNoProvinceOrLocal.pem'
        lint_dh_params_missing.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dsa_params_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
    '''
if __name__=="__main__":
    unittest.main(verbosity=2)