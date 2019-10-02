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
from bs4 import BeautifulSoup
from xml.etree import ElementTree as ET

logger = logging.getLogger("aadlogin")
handler = logging.StreamHandler(sys.stdout)
FORMAT = "[%(asctime)s][%(levelname)s] %(message)s"
handler.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(handler)
logger.setLevel(logging.INFO)


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

    parser.add_argument('-r', '--role',  required=True,
        help="role")            

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



    s = requests.Session()
    login_url = "https://login.microsoftonline.com"
    url = "https://account.activedirectory.windowsazure.com"
    main_url = "{}/applications/redirecttofederatedapplication.aspx?Operation=LinkedSignIn&applicationId={}".format(url, args.appid)



    r = s.get(main_url)
    result = re.search(r'\$Config=(.*);', r.text)
    start_saml = result.group(1)

    start_saml_json = (json.loads(start_saml))

    # data to be sent to api 
    data = {start_saml_json["sFTName"]: start_saml_json["sFT"], 
            'ctx':start_saml_json["sCtx"], 
            "login": args.username,
            "passwd": passwd,
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


    url = login_url + "/common/login"
    logger.info(f"SAML POST1 to: {url} ")
    r1 = s.post(url ,headers=headers,data=data)
    result = re.search(r'\$Config=(.*);', r1.text)
    kmsi_saml = result.group(1)
    kmsi_saml_json = (json.loads(kmsi_saml))



    url = login_url + kmsi_saml_json["urlPost"]
    logger.info(f"POST KMSI to: {url} ")
    kmsi_data = {
            kmsi_saml_json["sFTName"]: kmsi_saml_json["sFT"], 
            'ctx':kmsi_saml_json["sCtx"], 
            }
    r2 = s.post(url, headers=headers,data=kmsi_data)


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
    r3 = s.post(url, headers=headers,data=data)


    if "SAMLRequest" in r3.text:
        # print(r3.text)
        saml_request = re.search(r'(https:\/\/[a-zA-Z.\/\-]+)\/([a-zA-Z0-9\-]+)\/saml2\?SAMLRequest=([a-zA-Z0-9\-\%]+)', r3.text)
        url = saml_request.group(0)
        tenant_id = saml_request.group(2)
        logger.info(f"GET SAMLRequest")
        r5 = s.get(url)

        role_arn = None
        soup = BeautifulSoup(r5.text, 'html.parser')
        saml_response = soup.find('input', {'name': 'SAMLResponse'}).get('value')
        aws_roles = []
        for attribute in ET.fromstring(base64.b64decode(saml_response)).iter(
                '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if (attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
                for value in attribute.iter(
                        '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                    if args.role in value.text:
                        role_arn = value.text.split(',')[0]
                        principal_arn = value.text.split(',')[1]

                    aws_roles.append(value.text)

        
        if not role_arn:
            logger.warn("role not found")
        else:
            logger.info(f"STS assuming {role_arn}")

        response = boto3.client('sts').assume_role_with_saml(
            RoleArn=role_arn, 
            PrincipalArn=principal_arn,
            SAMLAssertion=saml_response, 
            DurationSeconds=3600
        )["Credentials"]

        print("export AWS_ACCESS_KEY_ID={}".format(response["AccessKeyId"]))
        print("export AWS_SECRET_ACCESS_KEY={}".format(response["SecretAccessKey"]))
        print("export AWS_SECURITY_TOKEN={}".format(response["SessionToken"]))

    else:
        print(" NO SAMLRequest ")
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.warn(" bye bye")
    