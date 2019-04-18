from cryptography import x509
from cryptography.x509.oid import ExtensionOID
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
class CrlCheck():
    def SplitUrl(self,cert,base):
        try:
            DistrubutionPoints = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for  distrubutionPoint in DistrubutionPoints.value:
                for Name in distrubutionPoint.full_name:
                    #print(Name)
                    if isinstance(Name,x509.UniformResourceIdentifier):
                        url = Name.value
                        filepath = base+'1.'+url.split('.')[-1]
                        try:
                            html = requests.get(url)
                            if html.status_code ==200:
                                with open(filepath,"wb") as f:
                                    f.write(html.content)
                                with open(filepath,"rb") as f:
                                    crl = x509.load_der_x509_crl(f.read(), default_backend())
                                    for r in crl:
                                        if cert.serial_number == r.serial_number:
                                            return "certificate had been revocated!"
                            return 0
                        except requests.exceptions.ConnectionError as e:
                            return str(e)
            return 0    
        except x509.ExtensionNotFound:
            return 0

if __name__=="__main__":
    certPath="C:\\Users\\dao\\Desktop\\2.cer"
    base ="D:\\myGitHub\\Plint\\crls\\"
    with open(certPath, "rb") as f:
            cert = x509.load_der_x509_certificate(f.read(), default_backend())
            print(CrlCheck().SplitUrl(cert,base))   