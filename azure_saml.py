from __future__ import print_function
import sys
import os
import re
import json
import requests
import base64
import boto3
import keyring
import argparse
import logging
import urllib
import time
import webbrowser
import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from xml.etree import ElementTree as ET

import ssl

logger = logging.getLogger("aadlogin")
handler = logging.StreamHandler(sys.stdout)
FORMAT = "[%(asctime)s][%(levelname)s] %(message)s"
handler.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class AADLogin(object):


    def __init__(self, args):
        self.args = args
        self.CACHE_FILE  = f"/tmp/aad_saml_{args.appid}.xml"
        self.saml_response = ""
        self.aws_roles = []
        self.role_arn = None
        self.principal_arn = None
        self.s = requests.Session()



    def assume_role_with_saml(self):
        logger.info(f"STS assuming {self.role_arn}")

        response = boto3.client('sts').assume_role_with_saml(
            RoleArn=self.role_arn,
            PrincipalArn=self.principal_arn,
            SAMLAssertion=self.saml_response,
            DurationSeconds=3600
        )["Credentials"]

        if self.args.open:

            url = self.get_console_url({
                'AccessKeyId': response["AccessKeyId"],
                'SecretAccessKey': response["SecretAccessKey"],
                'SessionToken': response["SessionToken"],
                'Region': "eu-central-1",
            }, "ec2")

            logger.debug('URL: {}'.format(url))
            try:
                webbrowser.open(url)
            except Exception as e:
                logger.error('Cannot open browser: {}'.format(e))
                logger.error('Here is the link: {}'.format(url))
        else:
            print("export AWS_ACCESS_KEY_ID={}".format(response["AccessKeyId"]))
            print("export AWS_SECRET_ACCESS_KEY={}".format(response["SecretAccessKey"]))
            print("export AWS_SECURITY_TOKEN={}".format(response["SessionToken"]))


    def parse_saml_response(self):
        logger.debug("SAML Response")
        if self.saml_response == "":
            with open(self.CACHE_FILE, 'r') as f:
                self.saml_response = f.read()
        else:
            logger.debug(base64.b64decode(self.saml_response))
            with open(self.CACHE_FILE, 'w') as f:
                f.write(self.saml_response)

        for attribute in ET.fromstring(base64.b64decode(self.saml_response)).iter(
                '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if (attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
                for value in attribute.iter(
                        '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                    if self.args.role:
                        if self.args.role in value.text:
                            self.role_arn = value.text.split(',')[0]
                            self.principal_arn = value.text.split(',')[1]


                    self.aws_roles.append(value.text)
        
        return self.aws_roles, self.role_arn, self.principal_arn

    def role_prompt(self):
        if not self.role_arn:
            logger.warn("role not found")
            alias = {}
            if os.path.exists("alias.json"):
                alias = json.load(open("alias.json", 'r'))

            if len(self.aws_roles) > 1:
                i = 0
                print("Please choose the role you would like to assume:")
                for awsrole in self.aws_roles:
                    account_id = awsrole.split(',')[0].split(":")[4]
                    acc_alias = alias.get(account_id, "noalias")

                    print('[{}]: {} - {}'.format(i, acc_alias, awsrole.split(',')[0]))
                    i += 1

                selectedroleindex = input("Selection: ")

                # Basic sanity check of input
                if int(selectedroleindex) > (len(self.aws_roles) - 1):
                    print('You selected an invalid role index, please try again')
                    sys.exit(0)

                self.role_arn = self.aws_roles[int(selectedroleindex)].split(',')[0]
                self.principal_arn = self.aws_roles[int(selectedroleindex)].split(',')[1]

            else:
                # only one role not needed to choose
                self.role_arn = self.aws_roles[0].split(',')[0]
                self.principal_arn = self.aws_roles[0].split(',')[1]



    def get_console_url(self, credentials: dict = None, destination: str = None):
        amazon_domain = 'amazonaws-us-gov' if 'gov' in str(credentials.get('Region')) else 'aws.amazon'
        logger.debug('Amazon domain: %s', amazon_domain)
        credentials = credentials if credentials is not None else {}
        logger.debug('Credentials: {}'.format(json.dumps(credentials, default=str, indent=2)))
        params = {
            'Action': 'getSigninToken',
            'Session': {
                'sessionId': credentials.get('AccessKeyId'),
                'sessionKey': credentials.get('SecretAccessKey'),
                'sessionToken': credentials.get('SessionToken'),
            },
        }

        logger.debug('Get console url request params: {}'.format(json.dumps(params, default=str, indent=2)))
        request_url = 'https://signin.' + amazon_domain + '.com/federation?'
        logger.debug(request_url + URLENCODE(params))
        response = URLOPEN(request_url + URLENCODE(params), context=ssl._create_unverified_context())
        raw = response.read()

        try:
            token = json.loads(raw)['SigninToken']
        except getattr(json.decoder, 'JSONDecoderError', ValueError):
            token = json.loads(raw.decode())['SigninToken']
        logger.debug('Signin token: {}'.format(token))
        region = credentials.get('Region') or 'us-east-1'
        logger.debug('Region: {}'.format(region))
        params = {
            'Action': 'login',
            'Issuer': '',
            'Destination': destination if is_url(destination) else 'https://console.' + amazon_domain + '.com/' + destination + '/home?region=' + region,
            'SigninToken': token
        }
        logger.debug('URL params: {}'.format(json.dumps(params, default=str, indent=2)))
        url = 'https://signin.' + amazon_domain + '.com/federation?'
        url += URLENCODE(params)
        return url

    def saml_cache_is_valid(self):
        if not os.path.exists(self.CACHE_FILE ):
            return False

        with open(self.CACHE_FILE , 'r') as f:
                saml_response = f.read()

        x = re.search('NotOnOrAfter="([0-9-T:\.Z]+)"', str(base64.b64decode(saml_response)))
        d = datetime.datetime.utcnow()
        date_time_obj = datetime.datetime.strptime(x.group(1), '%Y-%m-%dT%H:%M:%S.%fZ')

        if d > date_time_obj:
            logger.debug("SAML Cache expired")
            os.remove(self.CACHE_FILE )
            return False
        else:
            logger.debug("SAML Cache valid")
            return True




# Python 3 compatibility (python 3 has urlencode in parse sub-module)
URLENCODE = getattr(urllib, 'parse', urllib).urlencode
# Python 3 compatibility (python 3 has urlopen in parse sub-module)
URLOPEN = getattr(urllib, 'request', urllib).urlopen

def is_url(string: str) -> bool:
    return urlparse(string).scheme != ''





def get_cfg(text):
    result = re.search(r'\$Config=(.*);', text)
    return json.loads(result.group(1))





def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-u', '--username',
        help="username", default="giulio.calzolari@azure.example.com")

    parser.add_argument('-a', '--appid',
        help="app id", default="51e98410-035d-4403-99bd-729ba2224ff9")

    parser.add_argument('-k', '--key',
        help="key", default="aadlogin")

    parser.add_argument('-v',
                        '--verbose',
                        action='store_true',
                        help='an optional argument')

    parser.add_argument('--open',
                        action='store_true',
                        help='open browser')

    parser.add_argument('-r', '--role', help="role")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    passwd = keyring.get_password(args.key, args.username)
    if not passwd:
        _passwd = input(f"password for {args.username}: ")
        keyring.set_password(args.key, args.username, _passwd)
        keyring.get_password(args.key, args.username)
        passwd = keyring.get_password(args.key, args.username)
        if not passwd:
            logger.critical(f"error on saving password in {args.key}/{args.username}")
            sys.exit(1)

    a = AADLogin(args)

    if a.saml_cache_is_valid():
        logger.info("using local cache")
        a.parse_saml_response()
        a.role_prompt()
        sys.exit(0)

    login_url = "https://login.microsoftonline.com"
    url = "https://account.activedirectory.windowsazure.com"
    main_url = "{}/applications/redirecttofederatedapplication.aspx?Operation=LinkedSignIn&applicationId={}".format(url, args.appid)



    r = a.s.get(main_url)
    start_saml_json = get_cfg(r.text)
    # data to be sent to api
    data = {
        start_saml_json["sFTName"]: start_saml_json["sFT"],
        'ctx':start_saml_json["sCtx"],
        "login": args.username,
        "passwd": passwd
        }

    headers = {
        "Connection": "keep-alive",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en,en-US;q=0.9,fr;q=0.8,it;q=0.7",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"
        }

    headers_j = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"
        }


    url = login_url + "/common/login"
    logger.info(f"SAML POST1 to: {url} ")
    r1 = a.s.post(url ,headers=headers,data=data)

    if "DeviceAuthTls/reprocess" in r1.text:

        soup = BeautifulSoup(r1.text, 'html.parser')
        url = soup.find('form', {'name': 'hiddenform'}).get('action')
        logger.info(f"POST MFA to: {url} ")
        data = {
                "ctx" : soup.find('input', {'name': 'ctx'}).get('value'),
                "flowToken": soup.find('input', {'name': 'flowtoken'}).get('value'),
                }
        r_mfa = a.s.post(url, headers=headers,data=data)
        mfa_json = get_cfg(r_mfa.text)


        url = mfa_json["urlBeginAuth"]
        logger.info(f"POST SAS to: {url} ")
        data = {
                mfa_json["sFTName"]: mfa_json["sFT"],
                'ctx':mfa_json["sCtx"],
                "AuthMethodId": "PhoneAppNotification",
                "Method": "BeginAuth",
                }
        r = a.s.post(url, headers=headers_j ,json=data)
        bg = r.json()

        url = mfa_json["urlEndAuth"]
        success = False
        for x in range(30):
            time.sleep(1)
            data = {
                "FlowToken": bg["FlowToken"],
                'Ctx': bg["Ctx"],
                "AuthMethodId": "PhoneAppNotification",
                "Method": "EndAuth",
                "PollCount": x,
                "SessionId": bg["SessionId"]
                }


            r = a.s.post(url, headers=headers_j ,json=data).json()
            if r["ResultValue"] == "Success":
                print("success")
                success = True
                break

        if success:
            data = {
                "flowToken": r["FlowToken"],
                'request': bg["Ctx"],
                "mfaAuthMethod": "PhoneAppNotification"
                }
            url = mfa_json["urlPost"]
            logger.info(f"POST SAS EndAuth to: {url} ")
            r2 = a.s.post(url, headers=headers ,data=data)

        else:
            print("mfa error")
            sys.exit(1)


    else:
        # login without MFA
        kmsi_saml_json = get_cfg(r1.text)
        if kmsi_saml_json["urlPost"].startswith("https"):
            url = kmsi_saml_json["urlPost"]
        else:
            url = login_url + kmsi_saml_json["urlPost"]
        logger.info(f"POST KMSI to: {url} ")
        kmsi_data = {
                kmsi_saml_json["sFTName"]: kmsi_saml_json["sFT"],
                'ctx':kmsi_saml_json["sCtx"],
                }
        r2 = a.s.post(url, headers=headers,data=kmsi_data)


    soup = BeautifulSoup(r2.text, 'html.parser')
    url = soup.find('form', {'name': 'hiddenform'}).get('action')
    logger.info(f"POST FINAL to: {url} ")
    data = {
            "code" : soup.find('input', {'name': 'code'}).get('value'),
            "id_token": soup.find('input', {'name': 'id_token'}).get('value'),
            "state": soup.find('input', {'name': 'state'}).get('value'),
            "session_state": soup.find('input', {'name': 'session_state'}).get('value')
            }

    # print(r2.text)
    r3 = a.s.post(url, headers=headers,data=data)


    if "SAMLRequest" in r3.text:
        # print(r3.text)
        saml_request = re.search(r'(https:\/\/[a-zA-Z.\/\-]+)\/([a-zA-Z0-9\-]+)\/saml2\?SAMLRequest=([a-zA-Z0-9\-\%]+)', r3.text)
        url = saml_request.group(0)
        # tenant_id = saml_request.group(2)
        logger.info(f"GET SAMLRequest")
        r5 = a.s.get(url)

        soup = BeautifulSoup(r5.text, 'html.parser')
        a.saml_response = soup.find('input', {'name': 'SAMLResponse'}).get('value')
        a.parse_saml_response()
        a.role_prompt()
        a.assume_role_with_saml()

    else:
        logger.error(" NO SAMLRequest ")
        sys.exit(1)



if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.warn(" bye bye")
