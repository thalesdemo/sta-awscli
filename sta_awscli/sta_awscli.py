#!/usr/bin/env python3
__title__ = "MFA for AWS CLI using SafeNet Trusted Access (STA)"
__homepage__ = 'https://github.com/thalesdemo/sta-awscli'
__version__ = '2.1.3'
##########################################################################
# MFA for AWS CLI using SafeNet Trusted Access (STA)
##########################################################################
# Last updated on: 2022-08-31
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
import sys
import boto3
import requests
import configparser
import base64
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup
import os.path
from dateutil import tz
import validators
import numpy
import argparse
import argcomplete
import urllib.parse
import subprocess
from packaging.version import parse as parse_version
from requests.exceptions import ConnectionError
import colorama
import wget
import maskpass
import json
from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, ClientError, PinRequiredError, UserInteraction, WindowsClient
from fido2.webauthn import UserVerificationRequirement, PublicKeyCredentialDescriptor, \
                            PublicKeyCredentialType, PublicKeyCredentialRequestOptions
import fido2.client
import xmltodict
import logging

try:
    import readline
except ImportError:
    import pyreadline as readline


##########################################################################
# Variables
CONF_SECTION = 'config'
HOME_DIR = os.path.expanduser('~')
log = logging.getLogger(__name__)

class ErrorHandling:
    FIDO_ERROR_COUNTER = 0
    FIDO_FALLBACK_THRESHOLD = 2

class LocalStrings:
    USER_LANG_ISOCODE = None # defaults to 'en' if not specified

    IDP_DEFAULTS = {
        "account-not-verified": "We were unable to verify your account. Please check with your local administrator.",
        "not_authorized_to_access_app": "This application has not been assigned to you. Contact your administrator to be assigned.",
        "sms-challenge-sent-to-mobile-device": "Enter the passcode that was sent to you by email, text or voice message.",
        "access-denied": "Your access is denied.",
    }

    RUNTIME = {}

class BColors:
    BANNER = '\033[94m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ConfigFile:
    AWS_REGION = 'aws_region'
    KEYCLOAK_URL = 'cloud_idp'
    IS_KEYCLOAK_18_OR_HIGHER = 'is_new_kc'
    KC_TENANT_ID = 'tenant_reference_id'
    AWS_APP_NAME = 'aws_app_name'
    STA_USERNAME = 'sta_username'

class GridSureExtras:
    LINUX_GLIBC_FALLBACK_VERSION = '2.27' # is_old_glibc_installed == true if installed version strictly less
    FALLBACK_TESSERACT = \
    {
        'name':'tesseract-4.1.3-x86_64.GLIBC_2.22.AppImage',
        'url': 'https://github.com/AlexanderP/tesseract-appimage/releases/download/v4.1.3/tesseract-4.1.3-x86_64.GLIBC_2.22.AppImage',
    }
    LATEST_TESSERACT = \
    {
        'name': 'tesseract-5.2.0-x86_64.AppImage',
        'url': 'https://github.com/AlexanderP/tesseract-appimage/releases/download/v5.2.0/tesseract-5.2.0-x86_64.AppImage',
    }
    TESSERACT_LANGFILE = \
    {
        'name': 'snum',
        'url': f'{__homepage__}/raw/main/extras/snum.traineddata',
    }
    TESSERACT_WINDOWS = \
    {
        'name': 'tesseract.exe',
        'url': f'{__homepage__}/raw/main/extras/tesseract.exe'
    }

# Default choices for aws region
aws_region_list = [
        'eu-north-1', 'ap-south-1', 'eu-west-3', 'eu-west-2', 'eu-west-1', 'eu-central-1',
        'ap-northeast-3', 'ap-northeast-2', 'ap-northeast-1', 'ap-east-1', 'ap-southeast-1', 'ap-southeast-2',
        'sa-east-1', 'ca-central-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
]

# Default spacing for text output
spacing = 4 * ' '

# OCR dependency for GrIDsure (Tesseract-OCR)
class OCR:
    PATH = None
    OS = sys.platform
    CONFIG = '--psm 6 -c tessedit_char_whitelist=0123456789'

    def init():
        dirname = OCR.get_script_dir()
        filename = 'tesseract.exe' if OCR.is_windows() else 'tesseract'
        script_path = os.path.join(dirname, filename)

        if OCR.is_installed(filename):
            # Found Tesseract installed from system path or current working directory
            OCR.PATH = filename
            #TODO: Better handling in case 'snum' is not on the machine

        elif OCR.is_windows():
            if OCR.is_installed(script_path) or OCR.install_windows():
                # Found Tesseract under script path
                OCR.PATH = script_path
                lang_file_path = dirname
                OCR.CONFIG += f' --tessdata-dir "{lang_file_path}"'
            else:
                print(f'{BColors.WARNING} Failed to meet dependency - tesseract.exe not installed + auto-install failed or refused!{BColors.ENDC}\n')
                return False

        elif OCR.is_mac():
            if OCR.install_mac():
                OCR.PATH = filename
            else:
                return False

        elif OCR.is_linux():
            ocr_path = OCR.get_ocr_path()
            if OCR.is_installed(ocr_path) or OCR.install_linux():
                # found AppImage in script directory
                lang_file_path = dirname
                OCR.PATH = ocr_path
                OCR.CONFIG += f' --tessdata-dir "{lang_file_path}"'
            else:
                return False

        else:
            OCR.warning()
            OCR.PATH = None
            return False

        return True

    def warning():
        print(f'\n{BColors.WARNING}Tesseract could not be found on this machine and is required for GridSure login.')
        print(f'Please read instructions at: https://tesseract-ocr.github.io/tessdoc/Installation.html{BColors.ENDC}')

    def get_script_dir():
        return os.path.abspath(os.path.dirname(__file__))

    def is_windows():
        return OCR.OS == 'win32'

    def is_mac():
        return OCR.OS == 'darwin'

    def is_linux():
        return OCR.OS == 'linux' or OCR.OS == 'linux2'

    def is_installed(path):
        try:
            subprocess.call(path,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.STDOUT)
        except FileNotFoundError:
            return False

        return True

    def get_ocr_path():
        dirname = OCR.get_script_dir()

        if OCR.is_old_glibc_installed():
            appimage_package_name = GridSureExtras.FALLBACK_TESSERACT['name']
        else:
            appimage_package_name = GridSureExtras.LATEST_TESSERACT['name']

        return os.path.join(dirname, appimage_package_name)

    def is_old_glibc_installed(fallback_version = GridSureExtras.LINUX_GLIBC_FALLBACK_VERSION):
        command = 'ldd --version 2>&1 | head -n 1'
        output = subprocess.getoutput(command)

        glibc_version = ''.join(re.findall('([\d]+\.[\d]+)$', output))

        if parse_version(glibc_version) < parse_version(fallback_version):
            return True
        else:
            return False

    def appimage_picker():
        if OCR.is_old_glibc_installed():
            return GridSureExtras.FALLBACK_TESSERACT
        else:
            return GridSureExtras.LATEST_TESSERACT

    def set_file_permission(filename):
        try:
            current_permissions = os.stat(filename).st_mode
            print('\nSetting file permission (a+x): %s' % filename)
            os.chmod(filename, current_permissions | 0o111) # chmod a+x
            return True

        except FileNotFoundError:
            print('\nERROR: Could not find file to set permissions: %s' % filename)
            return False

        except PermissionError:
            while True:
                print(f'\n{BColors.WARNING}Not enough permissions to make the {filename} executable.')
                choice = input(f'Try using sudo? (y/n) {BColors.WHITE}')

                if(choice == 'n' or choice == 'no'):
                    return False

                if(choice == 'y' or choice == 'yes'):
                    rc = os.system(f'sudo chmod a+x {filename}')
                    if not rc:
                        print('Successfully updated file permission (a+x) for: %s !' % filename)
                        return True
                else:
                    print('Response not recognized - please provide correct response')

    def download(urls, path):
        for url in urls:
            filename = ''.join(url.split('/')[-1:])
            filepath = os.path.join(path, filename)
            if os.path.exists(filepath):
                while True:
                    print(f'\n{BColors.WARNING}File already exist: {filepath}.')
                    choice = input(f'\n{BColors.WHITE}Overwrite? (y/n) ')
                    if(choice == 'n' or choice == 'no'):
                        break
                    if(choice == 'y' or choice == 'yes'):
                        print(f'\nRemoving old file: {filepath}')
                        os.remove(filepath)
                        print(f'\nDownloading {url} to {path}:')
                        wget.download(url, out=path)
                        break
                    else:
                        print('Response not recognized - please provide correct response')
            else:
                print(f'\nDownloading {url} to {path}:')
                wget.download(url, out=path)


    def install_linux():
        OCR.warning()
        appimage = OCR.appimage_picker()
        appimage_url = appimage['url']
        appimage_package_name = appimage['name']
        language_file_url = GridSureExtras.TESSERACT_LANGFILE['url']
        urls = (
                appimage_url,
                language_file_url
        )
        dirname = OCR.get_script_dir()
        ocr_path = os.path.join(dirname, appimage_package_name)

        while True:
            choice = input(f'\n{BColors.WHITE}Install tesseract dependency from AppImage repository? (y/n) ')
            if(choice == 'n' or choice == 'no'):
                return False
            if(choice == 'y' or choice == 'yes'):
                try:
                    OCR.download(urls, dirname)
                except PermissionError:
                    while True:
                        print(f'\n{BColors.WARNING}Not enough permissions to save files to this path: {dirname}.')
                        choice = input(f'\n{BColors.WHITE}Try using sudo? (y/n) ')

                        if(choice == 'n' or choice == 'no'):
                            return False

                        if(choice == 'y' or choice == 'yes'):
                            for url in urls:
                                print(f'\n[SUDO] Downloading {url} to {dirname}:')
                                rc = os.system(f'sudo wget {url} -P {dirname}')
                                if not rc:
                                    print('Successfully saved file!')
                                else:
                                    print('Error during download of %s...' % url)
                                    return False
                            break
                        else:
                            print('Response not recognized - please provide correct response')

                if OCR.set_file_permission(ocr_path):
                    return True
            else:
                print('Response not recognized - please provide correct response')

    def install_mac():
        OCR.warning()
        while True:
            choice = input(f'\n{BColors.WHITE}Install tesseract dependency using brew? (y/n) ')
            if(choice == 'n' or choice == 'no'):
                return False
            if(choice == 'y' or choice == 'yes'):
                return os.system('brew install tesseract') == 0
            else:
                print('Response not recognized - please provide correct response')

    def install_windows():
        OCR.warning()
        urls = (
                GridSureExtras.TESSERACT_LANGFILE['url'],
                GridSureExtras.TESSERACT_WINDOWS['url']
        )
        dirname = OCR.get_script_dir()

        while True:
            choice = input(f'\n{BColors.WHITE}Install tesseract dependencies from our repository? (y/n) ')
            if(choice == 'n' or choice == 'no'):
                return False
            if(choice == 'y' or choice == 'yes'):
                OCR.download(urls, dirname)
                return True
            else:
                print('Response not recognized - please provide correct response')


##########################################################################
# Handle FIDO user interaction
class FidoUserInteraction(UserInteraction):
    def prompt_up(self):
        print(f'\n{BColors.WARNING}Touch your FIDO authenticator device now...{BColors.WHITE}\n')

    def request_pin(self, permissions, rd_id):
        return maskpass.askpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print(f"\n{BColors.WARNING}User Verification required.{BColors.WHITE}")
        return True

# # Monkey patching: Fix KeyVault or other tokens which do not have options['clientPin'] yet have options['uv'] defined
def monkey_patch_client_pin_is_supported(self, info):
    return "uv" in info.options or "clientPin" in info.options

fido2.client.ClientPin.is_supported = monkey_patch_client_pin_is_supported

# Monkey patching: Temporary until fido2 library incorporates their latest fix
from typing import Union
from fido2.utils import websafe_encode
import fido2.webauthn

@classmethod
def monkey_patch_create_clientcredential(
    cls,
    type: str,
    challenge: Union[bytes, str],
    origin: str,
    cross_origin: bool = False,
    **kwargs,
) -> fido2.webauthn.CollectedClientData:
    if isinstance(challenge, bytes):
        encoded_challenge = websafe_encode(challenge)
    else:
        encoded_challenge = challenge
    return cls(
        json.dumps(
            {
                "type": type,
                "challenge": encoded_challenge,
                "origin": origin,
                "crossOrigin": cross_origin,
                **kwargs,
            },
            separators=(",", ":"),
        ).encode()
    )

fido2.webauthn.CollectedClientData.create = monkey_patch_create_clientcredential

##########################################################################
# Arg parser

def setup_argparser():
    parser = argparse.ArgumentParser(
                description="On first execution, the script will collect the required information to create a configuration file (sta-awscli.config) that is stored in ~\.aws folder. " + \
                            "It's possible to run the script with -c switch to specify an alternative location for the config file or --update-config to overwrite existing configurations.",
                epilog=f"For more info, visit: {__homepage__}"
    )

    parser.add_argument(
            '-v', '--version',
            action='version',
            version=f'{check_software_version()}'

    )

    parser.add_argument(
            '-d', '--debug',
            action='store_true',
            dest='verbose',
            help='Enable verbose log to stdout & file (default: .\debug.log)'

    )

    parser.add_argument(
            '-c', '--config',
            required=False,
            dest='cli_config_path',
            default=os.path.join(HOME_DIR, '.aws', 'sta-awscli.conf'),
            help='Specify script configuration file path'
    )

    parser.add_argument(
            '--update-config',
            required=False,
            dest='update_config',
            action='store_true',
            help='Force update sta-awscli configuration file'
    )

    parser.add_argument(
            '-u', '--username',
            dest='username',
            default=None,
            help='Specify your SafeNet Trusted Access Username'
    )

    parser.add_argument(
        '-l', '--language',
        required=False,
        dest='isocode',
        default='en',
        help='Specify the short ISO code for the language locale, default: en'
    )

    region_group = parser.add_mutually_exclusive_group(required=False)
    region_group.add_argument(
            '-r',
            dest='region',
            nargs='?',
            default=[],
            const=True,
            help='Specify any AWS region (without input checking)'
    )
    region_group.add_argument(
            '--region',
            dest='region',
            nargs='?',
            default=[],
            const=True,
            type=str.lower,
            choices=aws_region_list,
            help='Specify AWS region (e.g. us-east-1)'
    )

    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    return args


##########################################################################
# Functions

def check_software_version():
    package='sta-awscli'
    url = f'https://pypi.org/pypi/{package}/json'
    author = '2022 - by Alex Basin, Gur Talmor & Cina Shaykhian'
    delimiter = lambda x : '\n' + str(x)*80 + '\n'

    print(package + ' (v' + __version__ + ') ' + author)

    try:
        response = requests.get(url)
        latest_version = response.json()['info']['version']

        update_available_message = f"""{BColors.OKGREEN}{delimiter('█')}
 ⚠️  A new version of sta-awscli is now available! (upgrade from {__version__} to {latest_version})\n
          Simply use the pip package manager to update:\n
          pip install --upgrade sta-awscli
        {delimiter('█')}{BColors.ENDC}"""

        no_update_available_message = \
            f'{BColors.OKCYAN}Check update: version matches the latest one available online!{BColors.ENDC}\n'

        if parse_version(latest_version) > parse_version(__version__):
            print(update_available_message)
        else:
            print(no_update_available_message)

    except (ConnectionError, KeyError):
        latest_version = None
        print(f'{BColors.WARNING}[!] Could not fetch latest version status: {url}{BColors.ENDC}\n')

    return f'Project homepage: {__homepage__}'


# removes the table borders
def transform_image(b64img):
    import cv2

    nparr = numpy.frombuffer(base64.b64decode(b64img), numpy.uint8)
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


def print_grid_challenge(raw_text):
    if not raw_text.endswith('\n'): # tmp fix spacing / for linux
        raw_text += '\n'

    print('\nGridSure Challenge:\n')
    spacing = ' ' * 5
    print(spacing + raw_text.replace(' ', spacing).replace('\n','\n\n' + spacing))


def complete_grid_login(grid_data):
    import pytesseract

    base64_grid_img = grid_data.split(',')[1]
    img = transform_image(base64_grid_img)

    pytesseract.pytesseract.tesseract_cmd = OCR.PATH
    raw_text = pytesseract.image_to_string(
                    img,
                    lang=GridSureExtras.TESSERACT_LANGFILE['name'],
                    config=OCR.CONFIG
    )

    print_grid_challenge(raw_text)
    return maskpass.askpass(prompt=f"{BColors.WHITE}Enter PIP:{BColors.ENDC} ", mask="*")


def complete_push_login(sps_url):
    sps_session = requests.Session()

    try:
        print('-> CTRL+C to enter manual OTP')
        response = sps_session.post(sps_url, verify=True)
    except KeyboardInterrupt:
        return None

    if response.ok:
        print('Push response OK')
        return ''.join(sps_url.split('/')[-1:]) # strip https://sps.us.safenetid.com/api/parkingspot/<code>
    else:
        return None


def get_fido_client(origin):
    import ctypes
    if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
        # Use the Windows WebAuthn API if available, and we're not running as admin
        client = WindowsClient(origin)
    else:

        device_list = []

        try:
            devices = CtapHidDevice.list_devices()
            while True:
                dev = next(devices)
                device_list.append(dev)
        except StopIteration:
            pass

        print("")
        dev = None
        number_of_devices = len(device_list)
        device_list.sort(key=lambda x: x.product_name.lower())

        if number_of_devices > 1:
            i = 0
            print(f"{BColors.OKGREEN}Please pick the FIDO token that you would like to use:{BColors.WHITE}\n")
            for device in device_list:
                print(spacing + '[', i, ']: ', device.product_name.replace('Fido', 'FIDO')) #, f"(CTAP{device.version})")
                i += 1
            try:
                selectedDevice = int(input(f"\nSelection: {BColors.ENDC}"))
                if selectedDevice < len(device_list):
                    dev = device_list[selectedDevice]
            except ValueError:
                dev = None

            if not dev:
                print(f"{BColors.WARNING}Invalid selection - please try again.{BColors.WHITE}")

        elif number_of_devices == 1:
            dev = device_list[0]

        if dev is not None:
            print("Use USB HID channel.")
        else:
            try:
                from fido2.pcsc import CtapPcscDevice

                dev = next(CtapPcscDevice.list_devices(), None)
                print("Use NFC channel.")
            except Exception as e:
                print("NFC channel search error:", e)

        if not dev:
            print(f"{BColors.FAIL}No FIDO device found{BColors.WHITE}")
            return None

        # Set up a FIDO 2 client using the origin https://example.com
        client = Fido2Client(dev, origin, user_interaction=FidoUserInteraction())

    return client


def complete_fido_login(fido_data, origin_url):

    base64_decode = lambda x : base64.urlsafe_b64decode(x + '=' * ((4 - len(x)) % 4))
    base64_encode = lambda x : base64.urlsafe_b64encode(x).decode('utf-8').rstrip('=')

    log.debug('Input fido_data (directly from IDP): %s' % fido_data)
    log.debug('Origin URL: %s' % origin_url)

    fido_data = json.loads(fido_data)
    challenge = fido_data['challenge']
    cred_id = fido_data['allowCredentials'][0]['id']
    timeout = fido_data['timeout']

    log.debug('Challenge: %s' % challenge)
    log.debug('Credential ID: %s' % cred_id)
    log.debug('Timeout value: %s' % fido_data['timeout'])

    challenge = base64_decode(challenge)
    cred_id = base64_decode(cred_id)

    allowCredentials = [
        PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY,
                    cred_id
        )
    ]

    log.debug('Allow credentials: %s' % allowCredentials)

    fido2_client = get_fido_client(origin_url)
    if not fido2_client: return None

    log.info('FIDO2 Client Info:\n%s' % fido2_client.info)

    try:
        user_verification = UserVerificationRequirement.DISCOURAGED

        # Check if user verifcation is supported by the authenticator
        if fido2_client.info.options.get("uv") \
                        or fido2_client.info.options.get("pinUvAuthToken") \
                        or fido2_client.info.options.get('clientPin'):

            if ErrorHandling.FIDO_ERROR_COUNTER >= ErrorHandling.FIDO_FALLBACK_THRESHOLD:
                user_verification = UserVerificationRequirement.DISCOURAGED
            else:
                user_verification = UserVerificationRequirement.PREFERRED
                print("Your authenticator supports user verification!")
        else:
            print("Your authenticator does not support user verification...")

        options = PublicKeyCredentialRequestOptions(
                        challenge=challenge,
                        timeout=timeout,
                        rp_id=fido_data["rpId"],
                        allow_credentials=allowCredentials,
                        user_verification=user_verification
                    )
        log.debug('FIDO client options: %s' % options)

        assertions = fido2_client.get_assertion(options)
        #ErrorHandling.FIDO_ERROR_COUNTER = 0 # assumes no exception, reset counter (optional, script never runs twice without exiting)

    except PinRequiredError:
        log.warning(f'{BColors.WARNING}AUTH FAIL: A PIN is required and has not been supplied - please try again.{BColors.ENDC}')
        return None

    except (ClientError, ValueError) as e:

        if hasattr(e, 'cause') and isinstance(e.cause, CtapError):
            if e.cause.code == CtapError.ERR.UV_INVALID:
                print(f'{BColors.FAIL}AUTH FAIL: Wrong biometric PIN. Please try again.{BColors.WHITE}')
                return None
            elif e.cause.code == CtapError.ERR.UV_BLOCKED:
                print(f'{BColors.FAIL}AUTH FAIL: Your authenticator is blocked. You can unlock your token through Chrome (or Windows control panel).{BColors.WHITE}')
                return None
            elif e.cause.code in (CtapError.ERR.PIN_INVALID, CtapError.ERR.PIN_BLOCKED, CtapError.ERR.PIN_AUTH_BLOCKED):
                print(f'{BColors.FAIL}PIN ERROR: %s{BColors.WHITE}' % e.cause.code)
                return None
            else:
                log.warning(f"{BColors.FAIL}%s (%s){BColors.WHITE}" % (str(e.cause).upper(), e.code))
        else:
            log.warning(f"{BColors.FAIL}ERROR: %s {BColors.WHITE}" % e)

        # Relaxed PIN enforcement policy
        ErrorHandling.FIDO_ERROR_COUNTER += 1
        if ErrorHandling.FIDO_ERROR_COUNTER >= ErrorHandling.FIDO_FALLBACK_THRESHOLD:
            print(f"{BColors.WARNING}Changing to relaxed enforcement upon next auth attempt...{BColors.WHITE}")

        return None

    assertion = assertions.get_response(0)

    log.debug('ASSERTION (raw): %s' % assertion)
    log.debug('ASSERTION client data (raw): %s' % assertion.client_data)
    log.debug('ASSERTION credential id (base64): %s' % base64_encode(assertion.credential_id))
    log.debug('ASSERTION signature (raw): %s' % assertion.signature)
    log.debug('ASSERTION signature (base64): %s' % base64_encode(assertion.signature))
    log.debug('ASSERTION user handle (string): %s' % assertion.user_handle)
    log.debug('ASSERTION auth data rp_id_hash (base64): %s' % base64_encode(assertion.authenticator_data.rp_id_hash))
    log.debug('ASSERTION auth data flags (raw): %s' % assertion.authenticator_data.flags)
    log.debug('ASSERTION auth data counter (raw): %s' % assertion.authenticator_data.counter)
    log.debug('ASSERTION auth data extension (raw): %s' % assertion.authenticator_data.extensions)
    log.debug('ASSERTION extension results (raw): %s' % assertion.extension_results)

    authenticator_data = assertion.authenticator_data.rp_id_hash  \
                        + (assertion.authenticator_data.flags).to_bytes(1, byteorder='big') \
                        + (assertion.authenticator_data.counter).to_bytes(4, byteorder='big')

    authenticator_data_length = len(authenticator_data)
    authenticator_data = base64_encode(authenticator_data)

    log.debug('ASSERTION auth data: %s' % authenticator_data)
    log.debug('ASSERTION auth data length (in bytes): %s' % authenticator_data_length)
    log.debug('ASSERTION challenge value: %s' % base64_encode(assertion.client_data.challenge))

    client_data_json = {
        "type": assertion.client_data.type,
        "challenge": base64_encode(assertion.client_data.challenge),
        "origin": assertion.client_data.origin,
        "crossOrigin": assertion.client_data.cross_origin
    }
    client_data_json = json.dumps(client_data_json, separators = (',',':')).encode('utf-8')
    client_data_json = base64_encode(client_data_json)

    log.debug('Value of ClientDataJSON (raw): %s' % client_data_json)
    log.debug('Value of ClientDataJSON (utf-8): %s' % client_data_json)
    log.debug('Value of ClientDataJSON (base64): %s' % client_data_json)

    response = {
        "authenticatorData": authenticator_data,
        "clientDataJSON": client_data_json,
        "signature": base64_encode(assertion.signature),
        "userHandle": ('' if not assertion.user_handle else assertion.user_handle)
    }
    log.debug('Value of "response" in fidoResult: %s' % response)

    assertion_response = {
        "id": base64_encode(assertion.credential_id),
        "rawId":base64_encode(assertion.credential_id),
        "response": response,
        "type": "public-key",
    }
    assertion_response = json.dumps(assertion_response, separators = (',', ':'))
    return assertion_response


def region_completer(text, state):
    options = [cmd for cmd in aws_region_list if cmd.startswith(text)]
    if state < len(options):
        return options[state]
    else:
        return None


def input_aws_region():
    aws_region = ''

    readline.parse_and_bind("tab: complete")
    readline.set_completer(region_completer) # turn on auto-complete for aws region
    readline.set_completer_delims('\n')

    while True:
        aws_region = input('\nEnter AWS Region (e.g. us-east-1): ')
        aws_regex = re.compile(r'[a-z]*-[a-z]*-[0-9]{1}')

        if re.match(aws_regex, aws_region):
            break
        else:
            print(f'{BColors.FAIL}Response not recognized - please provide a valid AWS Region{BColors.WHITE}')

    readline.parse_and_bind('set disable-completion on')

    return aws_region


def show_banner():
    ##########################################################################
    # STA welcome message:
    print(f'''\
--------------------------------------------------------------------------------
          Welcome to MFA for AWS CLI using SafeNet Trusted Access!
{BColors.BANNER}                 _                                        _ _
             ___| |_ __ _          __ ___      _____  ___| (_)  ({__version__})
            / __| __/ _` | _____  / _` \ \ /\ / / __|/ __| | |
            \__ \ || (_| ||_____|| (_| |\ V  V /\__ \ (__| | |
            |___/\__\__,_|        \__,_| \_/\_/ |___/\___|_|_|
{BColors.ENDC}
================================================================================
    ''')


def load_configuration(args):
    config = configparser.ConfigParser()

    if not args.update_config and os.path.exists(args.cli_config_path):
        if not os.path.isfile(args.cli_config_path):
            print(f'{BColors.WARNING}Error: You must include the configuration filename.{BColors.ENDC}')
            sys.exit(1)

        print(f'{BColors.OKGREEN}Loaded config: {BColors.WHITE}{BColors.BOLD}' + os.path.abspath(args.cli_config_path))
        config.read(args.cli_config_path)
    else:
        print(f'{BColors.WARNING}Config file does not exist (or being updated) - prompting for configs{BColors.WHITE}')

        # aws region selector
        if args.region in aws_region_list:
            aws_region = args.region
        else:
            aws_region = input_aws_region()

        keycloak_url = ''
        while True:
            keycloak_url = input('\nKeycloak URL (without HTTP/HTTPS): ')
            if validators.domain(keycloak_url):
                break
            else:
                print(f'{BColors.FAIL}Response not recognized - please provide a valid URL{BColors.ENDC}')

        is_keycloak_18_or_higher = ''
        while True:
            is_keycloak_18_or_higher = input('\nIs Keycloak version 18 or higher (y/n): ')
            if is_keycloak_18_or_higher.lower() == 'y' or is_keycloak_18_or_higher.lower() == 'n' or\
                    is_keycloak_18_or_higher.lower() == 'yes' or is_keycloak_18_or_higher.lower() == 'no':
                break
            else:
                print(f'{BColors.FAIL}Response not recognized - please provide correct response{BColors.ENDC}')

        kc_tenant_id = ''
        while True:
            kc_tenant_id = input('\nKeycloak Realm Name: ')
            if kc_tenant_id != '':
                break
            else:
                print(f'{BColors.FAIL}Response not recognized - tenant ID cannot be empty{BColors.ENDC}')

        aws_app_name = ''
        while True:
            aws_app_name = input('\nAWS Application Name in Keycloak: ')
            if aws_app_name != '':
                break
            else:
                print(f'{BColors.FAIL}Response not recognized - AWS App Name cannot be empty{BColors.ENDC}')

        sta_username = ''
        if args.username:
            sta_username = args.username
        else:
            save_username = ''
            while True:
                save_username = input('\nDo you want to save the STA username (y/n): ')
                if save_username.lower() == 'n' or save_username.lower() == 'no':
                    break
                elif save_username.lower() == 'y' or save_username.lower() == 'yes':
                    while True:
                        sta_username = input('\nEnter Username: ')
                        if sta_username != '':
                            break
                        else:
                            print(f'{BColors.FAIL}Response not recognized - STA username cannot be empty{BColors.ENDC}\n')
                    break
                else:
                    print(f'{BColors.FAIL}Response not recognized - please provide correct response{BColors.ENDC}\n')

        config[CONF_SECTION] = {}
        config[CONF_SECTION][ConfigFile.AWS_REGION] = aws_region
        config[CONF_SECTION][ConfigFile.KEYCLOAK_URL] = keycloak_url
        config[CONF_SECTION][ConfigFile.IS_KEYCLOAK_18_OR_HIGHER] = is_keycloak_18_or_higher
        config[CONF_SECTION][ConfigFile.KC_TENANT_ID] = kc_tenant_id
        config[CONF_SECTION][ConfigFile.AWS_APP_NAME] = urllib.parse.unquote(aws_app_name)
        config[CONF_SECTION][ConfigFile.STA_USERNAME] = sta_username

        base_directory = os.path.dirname(args.cli_config_path)
        if base_directory and not os.path.exists(base_directory):
            os.makedirs(os.path.dirname(args.cli_config_path))

        with open(args.cli_config_path, 'w') as filename:
            config.write(filename)

        print(f"{BColors.OKGREEN}\nConfig file created: {BColors.ENDC}" + os.path.abspath(args.cli_config_path))

    return config


def _init_locals_helper(url, etag=False):
    headers = {'User-Agent': f'STA-AWSCLI Agent {__version__}'}

    url = url.get('value')
    response = requests.get(url, headers=headers)

    language_url = None

    if etag:
        response = xmltodict.parse(response.text)['ListBucketResult']['Contents']
        response = [x for x in response if x['Key'] == (LocalStrings.USER_LANG_ISOCODE + '.json')]
        response = next(iter(response), None)
        if not response: return False

        etag_code = response['ETag'].strip('"')

        language_url = url + (LocalStrings.USER_LANG_ISOCODE + '.json') + '?' + etag_code

    else:
        languages = json.loads(response.text)['languages']
        #isoCodes = [language['isoCode'] for language in languages]
        result = [x for x in languages if x['isoCode'] == LocalStrings.USER_LANG_ISOCODE]
        origin = urllib.parse.urlparse(url)
        origin = origin.scheme + '://' + origin.netloc

        if not result: return False

        language_url = origin + result[0]['path']

    if language_url:
        log.debug('Found language ISO code in URL: %s' % language_url)
        response = requests.get(language_url, headers=headers)
        response = json.loads(response.text)

        # set runtime local dict
        LocalStrings.RUNTIME = response
        log.debug('Loaded language pack.')
        return True

    return False


def init_runtime_locals(soup):
    """Set localization texts in LocalStrings.RUNTIME
    :param soup: bs4 of idp html page
    """
    if not LocalStrings.RUNTIME:
        idp_locals_custom_url =  soup.find(id="customLanguageListUrl")

        if(idp_locals_custom_url):
            if _init_locals_helper(idp_locals_custom_url):
                return True
            else:
                log.debug('Not found lang requested (%s) in custom URL pack.' % LocalStrings.USER_LANG_ISOCODE)

        idp_locals_default_url = soup.find(id="localizationStoreUrl")

        if(idp_locals_default_url):
            if _init_locals_helper(idp_locals_default_url, etag=True):
                return True
            else:
                log.debug('Not found lang requested (%s) in default URL pack. ' % LocalStrings.USER_LANG_ISOCODE)

        # Apply default localization if above method (URL-requests) fail
        LocalStrings.RUNTIME = LocalStrings.IDP_DEFAULTS

    return True


def init():
    # If using Windows, coloroma.init() will cause anything sent to stdout
    # or stderr to have ANSI color codes converted to the Windows versions.
    # If you are already using an ANSI compliant shell, it won't do anything
    colorama.init()
    #print(colorama.ansi.clear_screen())
    args = setup_argparser()
    if args.verbose:
        logging.basicConfig(
                    level=logging.DEBUG,
                    format=f'%(asctime)s %(name)s.%(funcName)s:%(lineno)d [%(levelname)s] - %(message)s',
                    handlers=[
                        logging.FileHandler("debug.log", mode='a', encoding='utf-8'),
                        logging.StreamHandler()
                    ]
        )
        log.info('[INIT] Logging enabled to: debug.log')
    show_banner()
    config = load_configuration(args)
    LocalStrings.USER_LANG_ISOCODE = args.isocode # init isocode for locales

    return args, config


##########################################################################
# Main function

def main():
    args, config = init()

    # output format: The AWS CLI output format that will be configured in the
    # user profile (affects subsequent CLI calls)
    outputformat = 'json'

    # region: The default AWS region that this script will connect
    # to for all API calls (note that some regions may not work)
    if args.region:
        if args.region in aws_region_list:
            region = args.region
        else:
            region = input_aws_region()
    else:
        region = config.get(CONF_SECTION, ConfigFile.AWS_REGION)

    # awsconfigfile: The file where this script will store the temp
    # credentials under the user profile
    awsconfigfile = os.path.join(HOME_DIR, '.aws', 'credentials')

    # SSL certificate verification: Whether or not strict certificate
    # verification is done, False should only be used for dev/test
    sslverification = True

    ##########################################################################
    # SafeNet Trusted Access variables

    # cloud_idp: The FQDN for your cloud zone. Use "sta.eu.safenetid.com" for
    # EU hosted tenants and "sta.us.safenetid.com" for US hosted tenants
    cloud_idp = config.get(CONF_SECTION, ConfigFile.KEYCLOAK_URL)

    # is_new_kc = input("Running Keycloak 18+? (y/n) [n]: ")
    is_new_kc = config.get(CONF_SECTION, ConfigFile.IS_KEYCLOAK_18_OR_HIGHER)

    # tenant_reference_id: The unique ID for your virtual server, found in the
    # tenant specific console URL, in the User Portal URL or in metadata files
    tenant_reference_id = config.get(CONF_SECTION, ConfigFile.KC_TENANT_ID)

    # aws_app_name: The name you have given to the AWS app in the Identity Provider
    aws_app_name = urllib.parse.quote(config.get(CONF_SECTION, ConfigFile.AWS_APP_NAME))

    # idpentryurl: The URL for the STA IdP including all the variables we need
    if is_new_kc.lower() == 'y':
        idpentryurl = "https://" + cloud_idp + "/realms/" + tenant_reference_id + "/protocol/saml/clients/" + aws_app_name

    else:
        idpentryurl = "https://" + cloud_idp + "/auth/realms/" + tenant_reference_id + "/protocol/saml/clients/" + aws_app_name

    print(f"{BColors.ENDC}{BColors.OKGREEN}\nKeycloak AWS app: {BColors.WHITE}{BColors.BOLD}{idpentryurl}{BColors.ENDC}")

    # sas_user: The name you have given to the AWS app in the Identity Provider
    if args.username:
        sas_user = args.username
    elif config.has_option(CONF_SECTION, ConfigFile.STA_USERNAME):
        sas_user = config.get(CONF_SECTION, ConfigFile.STA_USERNAME)
    else:
        sas_user = None

    ##########################################################################
    # Debugging if you are having any major issues:
    # logging.basicConfig(level=logging.DEBUG)

    print(f'{BColors.WHITE}')
    # Initiate session handler
    session = requests.Session()

    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    response = session.get(idpentryurl, verify=sslverification)
    # Capture the idpauthformsubmiturl, which is the final url after all the 302s
    idpauthformsubmiturl = response.url
    assertion = ''

    while True:
        soup = BeautifulSoup(response.text, "html.parser")
        payload = {}

        login_form = soup.find(id="sas-login-form")

        # There is a login form, need to fill it and post it
        if login_form:

            # initialize localization strings, if not already the case
            init_runtime_locals(soup)

            # display any error message
            error_message = soup.find(id="errorMsgLblContent")
            if error_message:
                error_message = error_message.get('data-i18n')
                if error_message in LocalStrings.RUNTIME:
                    print('\n' + BColors.FAIL + LocalStrings.RUNTIME[error_message] + BColors.WHITE + '\n')
                    sas_user = None

            # display any info label
            challenge_message = soup.find(id="challenge-data")
            #if info_message: info_message = info_message.get('challenge-data', None)
            if challenge_message:
                challenge_message = challenge_message.get('data-i18n')
                if challenge_message in LocalStrings.RUNTIME:
                    print(BColors.OKGREEN + LocalStrings.RUNTIME[challenge_message] + BColors.WHITE)


            # Parse the response and extract all the necessary values
            for inputtag in login_form.find_all(re.compile('(INPUT|input)')):
                name = inputtag.get('name', '')
                value = inputtag.get('value', '')

                if "sas_user" in name.lower() and value == '':
                    # In STA the username field is called "sas_user"
                    if not sas_user:
                        sas_user = input("Enter Username: ")
                    else:
                        print(f'Username {BColors.OKGREEN}(auto-submit): {BColors.WHITE}{sas_user}')
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
                elif "fidopage" in name.lower():
                    origin = urllib.parse.urlparse(idpauthformsubmiturl)
                    origin = origin.scheme + '://' + origin.netloc
                    fido_data = soup.find(id="fido_data")["value"]
                    fido_response = complete_fido_login(fido_data, origin)
                    if not fido_response:
                        input("\nPress <ENTER> to continue.\n")
                    else:
                        payload['fidoStatus'] = 'SUCCESS'
                        payload['fidoResult'] = fido_response
                        payload['fidoPage'] = True
                        log.info('Ready to POST fido_response (fidoResult) to IDP: %s' % fido_response)
                        break

                elif "password" in name.lower():
                    # In case Password field also exists in the page, which is for "AD Password + OTP" Keycloak flow
                    pw = maskpass.askpass(prompt="Enter Password: ", mask="*")
                    payload[name] = pw
                elif "sas_response" in name:
                    # In case using STA and page is redirected for anx authentication request page
                    authentication_type = 'OTP'

                    grid_image = soup.find(id='GRIDSUREImage')
                    if grid_image:
                        if OCR.init():
                            authentication_type = 'GRID'
                        else:
                            print(f'\n{BColors.FAIL}A grid image was detected on the page but could not be rendered due to missing dependencies.{BColors.ENDC}')

                    for inputtag in login_form.find_all(re.compile('(label)')):
                        # Solving for Policy in STA with "AD Password + OTP"
                        if 'data-i18n' in inputtag.attrs and inputtag.attrs['data-i18n'] == 'ad-password-challenge':
                            authentication_type = 'AD Password'

                    if authentication_type == 'GRID':
                        password = complete_grid_login(grid_image.get('src'))

                    elif authentication_type != 'OTP':
                        password = maskpass.askpass(prompt="\nEnter Password: ", mask="*")

                    else:
                        print("\nEnter OTP:", end=' ')
                        password = input()
                        print('')

                    payload[name] = password
                else:
                    # Simply populate the parameter with the existing value (picks up hidden fields in the login form)
                    payload[name] = value


            # note: wasn't required but strange to have kvp '':''
            if '' in payload:
                payload.pop('')
            log.info('Payload: %s' % payload)

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
    if not assertion:
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
    if len(awsroles) > 1:
        while True:
            i = 0
            print(f"{BColors.OKGREEN}Please choose the role you would like to assume:{BColors.WHITE}\n")
            for awsrole in awsroles:
                print(spacing + '[', i, ']: ', awsrole.split(',')[0])
                i += 1
            selectedroleindex = input(f"\nSelection: {BColors.ENDC}")

            try:
                selection = int(selectedroleindex)
            except ValueError:
                selection = -1

            if selection > (len(awsroles) - 1) or selection < 0:
                print('You selected an invalid role index, please try again')
            else:
                role_arn = awsroles[selection].split(',')[0]
                principal_arn = awsroles[selection].split(',')[1]
                break

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

    # Read in the existing config file
    config = configparser.RawConfigParser()
    config.read(awsconfigfile)

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
    with open(awsconfigfile, 'w+') as filename:
        config.write(filename)

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
    print(f'{BColors.OKGREEN}{BColors.BOLD}')
    print('Great job! You have now obtained temporary credentials for AWS CLI')
    print(f'NOTE: These credentials will expire at {local_time}.{BColors.ENDC}{BColors.WHITE}')
    print('Simply run the script again to refresh credentials on expiry.')
    print('You can use the above credentials to connect using AWS CLI. For example:')
    print(f'aws --profile {sas_user} ec2 describe-instances --region={region}')


if __name__ == "__main__":
    main()
