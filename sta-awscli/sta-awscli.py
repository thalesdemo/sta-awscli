""" MFA for AWS CLI using SafeNet Trusted Access (STA) """
__version__ = "2.0.0"

##########################################################################
# MFA for AWS CLI using SafeNet Trusted Access (STA)
##########################################################################
# version: 2.0
# last updated on: 2022-08-25
#
#
# NOTE: This script was adapted from a script written by Quint Van Deman
# published on the AWS Security Blog (https://amzn.to/2gT8IAZ). Notable
# changes includes that SafeNet Trusted Access (STA) is used instead of
# Microsoft AD FS and that two forms are used instead of one as STA will
# collect only username on the first page to premiere Push OTP over manual
# credential input. Moreover, the script sets temporary access tokens in
# the profile of the authenticated user instead of in SAML profile.
#
# The script supports all SafeNet Trusted Access authentication methods,
# including trigger based methods such as Push (triggered using "p" or blank OTP)
# and GriDsure (triggered using "g")
#
# LIMITATIONS/ KNOWN ISSUES: GridSure support is experimental and requires
# tesseract v4.0 and above to be installed on the host
# (https://tesseract-ocr.github.io/tessdoc/Installation.html)
#
# ************************************************************************
# DISCLAIMER: This script is provided "as-is" without any warranty of
# any kind, either expressed or implied.
# ************************************************************************
# !/usr/bin/python3
import sys
import boto3
import requests
import configparser
import base64
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup
from os.path import expanduser
import os.path
from dateutil import tz
import validators
import pwinput
import numpy

##########################################################################
# AWS variables

class BColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ConfigFile:
    AWS_REGION = 'aws_region'
    KEYCLOAK_URL = 'cloud_idp'
    IS_KEYCLOAK_18_OR_HIGHER = 'is_new_kc'
    KC_TENANT_ID = 'tenant_reference_id'
    AWS_APP_NAME = 'aws_app_name'


CONF_SECTION = 'config'
cli_config_file_path = 'sta-awscli.conf'

config = configparser.ConfigParser()

if os.path.exists(cli_config_file_path):
    absolute_path = os.path.abspath(cli_config_file_path)
    print(f'{BColors.OKGREEN}Config file found in: {BColors.ENDC}' + absolute_path)
    config.read(cli_config_file_path)
else:
    print(f'{BColors.WARNING}Config file not found - prompting for configs{BColors.ENDC}\n')
    aws_region = ''
    while True:
        aws_region = input('Enter AWS Region (e.g. us-east-1): ')
        aws_regex = re.compile(r'[a-z]*-[a-z]*-[0-9]{1}')

        if re.match(aws_regex, aws_region):
            break
        else:
            print(f'{BColors.FAIL}Response not recognized - please provide a valid AWS Region{BColors.ENDC}\n')

    keycloak_url = ''
    while True:
        keycloak_url = input('KeyCloak URL (without HTTP/HTTPS): ')
        if validators.domain(keycloak_url):
            break
        else:
            print(f'{BColors.FAIL}Response not recognized - please provide a valid URL{BColors.ENDC}\n')

    is_keycloak_18_or_higher = ''
    while True:
        is_keycloak_18_or_higher = input('Is KeyCloak version 18 or higher (y/n): ')
        if is_keycloak_18_or_higher.lower() == 'y' or is_keycloak_18_or_higher.lower() == 'n' or\
                is_keycloak_18_or_higher.lower() == 'yes' or is_keycloak_18_or_higher.lower() == 'no':
            break
        else:
            print(f'{BColors.FAIL}Response not recognized - please provide correct response{BColors.ENDC}\n')

    kc_tenant_id = ''
    while True:
        kc_tenant_id = input('KeyCloak Realm Name: ')
        if kc_tenant_id != '':
            break
        else:
            print(f'{BColors.FAIL}Response not recognized - tenant ID cannot be empty{BColors.ENDC}\n')

    aws_app_name = ''
    while True:
        aws_app_name = input('AWS Application Name in KeyCloak: ')
        if aws_app_name != '':
            break
        else:
            print(f'{BColors.FAIL}Response not recognized - AWS App Name cannot be empty{BColors.ENDC}\n')

    config[CONF_SECTION] = {}
    config[CONF_SECTION][ConfigFile.AWS_REGION] = aws_region
    config[CONF_SECTION][ConfigFile.KEYCLOAK_URL] = keycloak_url
    config[CONF_SECTION][ConfigFile.IS_KEYCLOAK_18_OR_HIGHER] = is_keycloak_18_or_higher
    config[CONF_SECTION][ConfigFile.KC_TENANT_ID] = kc_tenant_id
    config[CONF_SECTION][ConfigFile.AWS_APP_NAME] = aws_app_name

    with open(cli_config_file_path, 'w') as configfile:
        config.write(configfile)

    print(f"{BColors.OKGREEN}Config file created in: {BColors.ENDC}" + os.path.abspath(cli_config_file_path))


# region: The default AWS region that this script will connect
# to for all API calls (note that some regions may not work)

region = config.get(CONF_SECTION, ConfigFile.AWS_REGION)

# output format: The AWS CLI output format that will be configured in the
# user profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile: The file where this script will store the temp
# credentials under the user profile
awsconfigfile = '/.aws/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

##########################################################################
# SafeNet Trusted Access variables

# cloud_idp: The FQDN for your cloud zone. Use "sta.eu.safenetid.com" for
# EU hosted tenants and "sta.us.safenetid.com" for US hosted tenants
cloud_idp = config.get(CONF_SECTION, ConfigFile.KEYCLOAK_URL)

# is_new_kc = input("Running KeyCloak 19+? (y/n) [n]: ")
is_new_kc = config.get(CONF_SECTION, ConfigFile.IS_KEYCLOAK_18_OR_HIGHER)

# tenant_reference_id: The unique ID for your virtual server, found in the
# tenant specific console URL, in the User Portal URL or in metadata files
tenant_reference_id = config.get(CONF_SECTION, ConfigFile.KC_TENANT_ID)

# aws_app_name: The name you have given to the AWS app within the STA console
# use "%20" (excluding "") instead of any blank spaces
aws_app_name = config.get(CONF_SECTION, ConfigFile.AWS_APP_NAME)

# idpentryurl: The URL for the STA IdP including all the variables we need


if is_new_kc.lower() == 'y':
    idpentryurl = "https://" + cloud_idp + "/realms/" + tenant_reference_id + "/protocol/saml/clients/" + aws_app_name

else:
    idpentryurl = "https://" + cloud_idp + "/auth/realms/" + tenant_reference_id + "/protocol/saml/clients/" + aws_app_name

print("KeyCloak AWS application URL: " + idpentryurl)
sas_user = None


##########################################################################
# Debugging if you are having any major issues:

# logging.basicConfig(level=logging.DEBUG)

##########################################################################
# STA welcome message:
print(f'''
-----------------------------------------------------------------------------------------
Welcome to MFA for AWS CLI using:{BColors.HEADER}
  ___        __     _  _     _     _____            _          _     _                   
 / __| __ _ / _|___| \| |___| |_  |_   _| _ _  _ __| |_ ___ __| |   /_\  __ __ ___ ______
 \__ \/ _` |  _/ -_) .` / -_)  _|   | || '_| || (_-<  _/ -_) _` |  / _ \/ _/ _/ -_|_-<_-<
 |___/\__,_|_| \___|_|\_\___|\__|   |_||_|  \_,_/__/\__\___\__,_| /_/ \_\__\__\___/__/__/
{BColors.ENDC}                                                                                         
=========================================================================================
''')

# Initiate session handler
session = requests.Session()

# Opens the initial IdP url and follows all of the HTTP302 redirects, and
# gets the resulting login page
response = session.get(idpentryurl, verify=sslverification)
# Capture the idpauthformsubmiturl, which is the final url after all the 302s
idpauthformsubmiturl = response.url
assertion = ''


# removes the table borders
def transform_image(b64img):
    import cv2

    nparr = numpy.frombuffer(b64img, numpy.uint8)
    image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    result = image.copy()
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)[1]

    # Remove horizontal lines
    horizontal_kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (40,1))
    remove_horizontal = cv2.morphologyEx(thresh, cv2.MORPH_OPEN, horizontal_kernel, iterations=2)
    cnts = cv2.findContours(remove_horizontal, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    cnts = cnts[0] if len(cnts) == 2 else cnts[1]
    for c in cnts:
        cv2.drawContours(result, [c], -1, (255,255,255), 5)

    # Remove vertical lines
    vertical_kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (1,40))
    remove_vertical = cv2.morphologyEx(thresh, cv2.MORPH_OPEN, vertical_kernel, iterations=2)
    cnts = cv2.findContours(remove_vertical, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    cnts = cnts[0] if len(cnts) == 2 else cnts[1]
    for c in cnts:
        cv2.drawContours(result, [c], -1, (255,255,255), 5)

    #cv2.imwrite('result.png', result)
    return result


def complete_grid_login(grid_data):
    import pytesseract

    decoded_grid_data = base64.b64decode(grid_data.split(',')[1])
    img = transform_image(decoded_grid_data) 

    custom_config = '--psm 6 -c tessedit_char_whitelist=0123456789'
    raw_text = pytesseract.image_to_string(img, lang='snum', config=custom_config)

    print('\nGrIDsure Challenge:\n')
    print(raw_text.replace(' ', '     ').replace('\n','\n\n'))

    pip = pwinput.pwinput(prompt="Enter PIP: ", mask="*")
    return pip


def complete_push_login(sps_url):
    sps_session = requests.Session()

    try:
        print('-> CTRL+C to enter manual OTP')
        response = sps_session.post(sps_url, verify=sslverification)
    except KeyboardInterrupt:
        return None
    
    if response.ok:
        print('Push response OK')
        return ''.join(value.split('/')[-1:]) # need to strip https://sps.us.safenetid.com/api/parkingspot/<code>
    else:
        return None


while True:
    # print(response.text)
    soup = BeautifulSoup(response.text, "html.parser")
    payload = {}

    login_form = soup.find(id="sas-login-form")

    # There is a login form, need to fill it and post it
    if login_form:
        # Parse the response and extract all the necessary values
        for inputtag in login_form.find_all(re.compile('(INPUT|input)')):
            name = inputtag.get('name', '')
            value = inputtag.get('value', '')

            if "sas_user" in name.lower() and value == '':
                # In STA the username field is called "sas_user"
                # Prompt for STA username
                sas_user = input("Enter Username: ")
                payload[name] = sas_user
            elif "sas_push" in name.lower():
                sps_response = complete_push_login(value)
                if sps_response:
                    payload['authenticationId'] = sps_response
                    payload['pushOtpSpsStatus'] = "RESPONSE_AVAILABLE"
                    break

                else:
                    payload.pop('authenticationId', None)
                    payload['pushtype'] = ''
                    payload.pop('pushOtpSpsStatus', None)
                    payload.pop('pushPage', None)

                print('\n')
            elif "password" in name.lower():
                # In case Password field also exists in the page, which is for "AD Password + OTP" KeyCloak flow
                pw = pwinput.pwinput(prompt="Enter Password: ", mask="*")
                payload[name] = pw
            elif "sas_response" in name:
                # In case using STA and page is redirected for anx authentication request page
                authentication_type = 'OTP'

                grid_image = soup.find(id='GRIDSUREImage')
                if grid_image:
                    authentication_type = 'GRID'

                for inputtag in login_form.find_all(re.compile('(label)')):
                    # Solving for Policy in STA with "AD Password + OTP"
                    if 'data-i18n' in inputtag.attrs and inputtag.attrs['data-i18n'] == 'ad-password-challenge':
                        authentication_type = 'AD Password'

                if authentication_type == 'GRID':
                    password = complete_grid_login(grid_image.get('src'))

                elif authentication_type != 'OTP':
                    password = pwinput.pwinput(prompt="Enter Password: ", mask="*")

                else:
                    print("Enter OTP:", end=' ')
                    password = input()

                payload[name] = password
            else:
                # Simply populate the parameter with the existing value (picks up hidden fields in the login form)
                payload[name] = value
               

        # note: wasn't required but strange to have kvp '':''
        if '' in payload:
            payload.pop('')
        #print(payload)
        
        idpauthformsubmiturl = login_form.get('action')
        
        #print(idpauthformsubmiturl)
        # Performs the submission of the STA login form with the above post data
        response = session.post(idpauthformsubmiturl, data=payload, verify=sslverification)
        continue

    redirect_page = soup.find("form", {"name": "saml-post-binding"})

    if redirect_page:
        # Detecting redirection case - need to redirect and keep consuming pages
        for inputtag in redirect_page.find_all(re.compile('(INPUT|input)')):
            name = inputtag.get('name', '')
            value = inputtag.get('value', '')

            if name != '':
                payload[name] = value

        redirect_url = redirect_page['action']
        assertion = redirect_page.find("input", {"name": "SAMLResponse"})
        if assertion:
            assertion = assertion['value']

        response = session.post(redirect_url, data=payload, verify=sslverification)
        continue

    break


# Better error handling is required for production use.
if (assertion == ''):
    # TODO: Insert valid error checking/handling
    sys.exit('Ooops! Wrong username/password or the response did not contain a valid SAML assertion')

# Debug only
# print(base64.b64decode(assertion))

# Parse the returned assertion and extract the authorized roles
awsroles = []
root = ET.fromstring(base64.b64decode(assertion))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)

# Note the format of the attribute value should be role_arn,principal_arn
# but lots of blogs list it as principal_arn,role_arn so let's reverse
# them if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if 'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# If I have more than one role, ask the user which one they want,
# otherwise just proceed
print("")
if len(awsroles) > 1:
    #print(awsroles) For debug purposes
    i = 0
    print("Please choose the role you would like to assume:")
    for awsrole in awsroles:
        print('[', i, ']: ', awsrole.split(',')[0])
        i += 1
    print("Selection: ", end=' ')
    selectedroleindex = input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
        sys.exit('You selected an invalid role index, please try again')

    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
elif len(awsroles) > 0:
    role_arn = awsroles[0].split(',')[0]
    principal_arn = awsroles[0].split(',')[1]
else:
    print(f'No role assigned to user "{sas_user}".')
    sys.exit("Please assign role to user and try again.")

# Use the assertion to get an AWS STS token using Assume Role with SAML
client = boto3.client('sts', region_name=region)

token = client.assume_role_with_saml(
    RoleArn=role_arn,
    PrincipalArn=principal_arn,
    SAMLAssertion=assertion,
    DurationSeconds=14400
)

# token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile

# Read in the existing config file
config = configparser.RawConfigParser()
config.read(filename)

# Put the credentials into the STA user's profile
# TODO: Consider (option)to export the keys/token as environmental variables
if not config.has_section(sas_user):
    config.add_section(sas_user)

config.set(sas_user, 'output', outputformat)
config.set(sas_user, 'region', region)
config.set(sas_user, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
config.set(sas_user, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
config.set(sas_user, 'aws_session_token', token['Credentials']['SessionToken'])

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

##########################################################################
# Provide user feedback

# Provide token expiry in a more friendly format
# TODO: Ideally the value should be presented in user local timezone
# expiry_dt = datetime.datetime.fromisoformat(token['Credentials']['Expiration'].replace("Z", "+00:00")).strftime(
#     "%Y-%m-%d %H:%M:%S")

expiry_dt = token['Credentials']['Expiration']
from_zone = tz.tzutc()
to_zone = tz.tzlocal()

expiry_dt_in_utc = expiry_dt.replace(tzinfo=from_zone)
local_time = expiry_dt_in_utc.astimezone(to_zone).strftime("%m/%d/%Y, %H:%M:%S")

# Provide some user feedback:
print('Great job! You have now obtained temporary credentials for AWS CLI')
print('NOTE: These credentials will expire at {0}.'.format(local_time))
print('Simply run the script again to refresh credentials on expiry.')
print('You can use the above credentials to connect using AWS CLI. For example:')
print(f'aws --profile {sas_user} ec2 describe-instances --region={region}\n')
