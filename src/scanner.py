import requests
import socket
import ssl
import re

def scanner():
    domain = input("Enter the server address: ")
    try:
        res = requests.get(domain)
        head = res.headers()
        auth_data = {'Content-Security-Policy': head.get('Content-Security-Policy', 'Missing'),
            'Strict-Transport-Security': head.get('Strict-Transport-Security', 'Missing'),
            'X-Content-Type-Options': head.get('X-Content-Type-Options', 'Missing'),
            'X-Frame-Options': head.get('X-Frame-Options', 'Missing'),
            'X-XSS-Protection': head.get('X-XSS-Protection', 'Missing')}
        print(f"Security headers status \n")
        for header, status in auth_data.items():
            print(f"{header}: {status}")
        check_https(domain)
    except Exception as e:
        print(f"Error: {e}")

def check_https(domain):
    print("als")
    cert = ssl.create_defaul_context() #Manage security configuration
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((domain, 443))

if __name__ == "__main__":
    scanner()