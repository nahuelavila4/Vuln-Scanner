import requests
import socket
import ssl
import re
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scanner():
    dom = input("Enter the server address: ")
    try:
        res = requests.get(dom, verify=False)
        head = res.headers
        auth_data = {'Content-Security-Policy': head.get('Content-Security-Policy', 'Missing'),
            'Strict-Transport-Security': head.get('Strict-Transport-Security', 'Missing'),
            'X-Content-Type-Options': head.get('X-Content-Type-Options', 'Missing'),
            'X-Frame-Options': head.get('X-Frame-Options', 'Missing'),
            'X-XSS-Protection': head.get('X-XSS-Protection', 'Missing')}
        print(f"Security headers status \n")
        for header, status in auth_data.items():
            print(f"{header}: {status}")
        check_https("localhost", 8080)
    except Exception as e:
        print(f"Error: {e}")

def check_https(domain, port):
    context = ssl.create_default_context() #Manage security configuration
    context.check_hostname = False  # Ignorar la verificación del nombre
    context.verify_mode = ssl.CERT_NONE  # No verificar el certificado

    with socket.create_connection((domain, port)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert() #Retrieve SSL certificate
            print(cert['NotAfter'])
            '''
            exp_date = cert['NotAfter']
            exp_obj = datetime.strptime(exp_date, "%b %d %H:%M:%S %Y GMT")
            act_date = datetime.now()
            if exp_obj > act_date:
                print("The SSL certificate has expired")
            else:
                print("The SSL certificate is valid")
            '''
    return cert

if __name__ == "__main__":
    scanner()