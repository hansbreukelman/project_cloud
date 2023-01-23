
from requests import get

trusted_ip = get('https://api.ipify.org').text

# trusted_ip = urllib3.request.urlopen('https://api.ipify.org').read().decode('utf8')

# print(trusted_ip)