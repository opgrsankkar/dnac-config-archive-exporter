import jwt
import time
import requests
import configparser
from os.path import expanduser
from getpass import getpass

# Disable warnings
requests.packages.urllib3.disable_warnings()

class MaglevConf():
    def get_from_user_input(self):
        url = input("Enter the URL of the DNAC: ")
        url = f"https://{url}" if not ("http" in url) else url
        username = input("Enter the username: ")
        token = get_token_from_auth(url, username, getpass(f'DNAC GUI password for "{username}": '))
        return url, username, token
    def __init__(self, url=None, username=None, token=None, context=None):
        user_home_path = expanduser("~")
        self.config = configparser.ConfigParser()
        try:
            self.config.read_file(open(f"{user_home_path}/.maglevconf"), 'r')
            self.file_exists = True
        except FileNotFoundError:
            self.file_exists = False
        if not self.file_exists:
            url, username, token = self.get_from_user_input()
            self.config['maglev-1'] = {
                'url': url,
                'username': username,
                'token': token,
                'insecure': 'True',
                'repository': 'main'
            }
            self.config['global'] = {
                'default_context': 'maglev-1'
            }
            with open(f"{user_home_path}/.maglevconf", 'w+') as configfile:
                self.config.write(configfile)
        self.context = context or self.config.get('global', 'default_context')
        self.context_config = self.config[self.context]

    def get(self, key):
        try:
            return self.context_config.get(key)
        except configparser.NoOptionError:
            return None

    def set(self, key, value):
        self.context_config[key] = value
        with open("/home/maglev/.maglevconf", 'w') as configfile:
            self.config.write(configfile)

    def get_url(self):
        return self.get('url')

    def get_username(self):
        return self.get('username')

    def get_token(self):
        token = self.get('token')
        if token:
            decoded_token = jwt.decode(token, verify=False, options={"verify_signature": False})
            if decoded_token.get('exp') < time.time():
                token = None
        return token

    def set_url(self, url):
        url = f"https://{url}" if not ("http" in url) else url
        self.set('url', url)

    def set_username(self, username):
        self.set('username', username)

    def set_token(self, token):
        self.set('token', token)

def get_token_from_auth(host, username, password):
    url = f"{host}/dna/system/api/v1/auth/token"
    headers = {
        "Content-Type": "application/json",
    }
    response = requests.post(url, headers=headers, auth=(username, password), verify=False)
    response.raise_for_status()
    token = response.json()["Token"]
    return token

def setup_variables():
    maglevconf = MaglevConf()
    url = maglevconf.get_url()
    username = maglevconf.get_username()
    token = maglevconf.get_token()
    if token is None:
        password = getpass(f'DNAC GUI password for "{username}": ')
        token = get_token_from_auth(url, username, password)
        maglevconf.set_token(token)
    return url, username, token

# get the URL, username and password
host, username, token = setup_variables()
headers = {
    "X-Auth-Token": token,
    "Content-Type": "application/json",
}

# get the list of devices to download the config
devices_raw_input = input("Enter the list of device IPs separated by comma: ")
# clean the input for whitespaces and split it into a list
device_ips = [device.strip() for device in devices_raw_input.split(",")]

# get the device ids from the IP addresses
device_ids = []
for device in device_ips:
    url = f"{host}/dna/intent/api/v1/network-device/ip-address/{device}"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    device_id = response.json()["response"]["id"]
    device_ids.append(device_id)

# get the config for devices
get_config_url = f"{host}/dna/intent/api/v1/network-device-archive/cleartext"
response = requests.post(get_config_url, headers=headers, json={"deviceId": device_ids, "password": "Bundle@123"}, verify=False)
response.raise_for_status()
task_url = response.json()["response"]["url"]


while True:
    response = requests.get(f"{host}{task_url}", headers=headers, verify=False)
    response.raise_for_status()
    task_status = response.json()["response"]
    if "endTime" in task_status:
        break
    else:
        time.sleep(1)

if task_status["isError"] == True:
    print(task_status["progress"])
    exit(1)

# get the file URL
file_url = f"{host}{task_status['additionalStatusURL']}"
response = requests.get(file_url, headers=headers, verify=False)
response.raise_for_status()
with open("config_archive.zip", "wb") as f:
    f.write(response.content)

print('Device configuration Successfully exported to file "config_archive.zip"')
print('File is protected with password "Bundle@123"')