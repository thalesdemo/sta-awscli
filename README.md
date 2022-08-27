# sta-awscli
## MFA for AWS CLI using SafeNet Trusted Access (STA)


This script allows using SafeNet Trusted Access (STA) IDP based authentication when working with AWSCLI. At the moment, the supported configuration is using Keycloak (https://www.keycloak.org) as an "agent" between STA and AWS, allowing us to support AWS with multiple accounts and roles.
The script assumes STA and Keycloak are configured and working for SAML based access to AWS.

The script supports all STA authentication methods, including manual OTP, Push based OTP and GriDsure.
GriDsure support is experimental and requires "tesseract" v4.0 and above to be installed on the host (https://tesseract-ocr.github.io/tessdoc/Installation.html).

## Configuration

On first execution, the script will collect the required information to create a configuration file (sta-awscli.config) that is stored in ~\.aws folder. It's possible to run the script with -c switch to specify an alternative location for the config file.  
The configuration file includes:  

- AWS Region
- Keycloak URL
- Keycloak version
- Keycloak Realm Name
- AWS application name in Keycloak

For example:
```
[config]
aws_region =  
cloud_idp =  
is_new_kc =  
tenant_reference_id =  
aws_app_name =  
```
## Usage

Once the configuration is created, a connection is established to STA through Keycloak and the user will be asked to provide a username, based on STA authentication policy, AD Password and OTP. If the user only has single token (MobilePASS+ or GriDsure) assigned, the authentication will be triggered automatically (Push for MobilePASS+ or the pattern grid presented for GriDsure). For auto triggered Push - the user can cancel the Push using CTRL+C to manually enter OTP.
If the user has multiple tokens assigned, the user is aksed to provide an OTP, but still has the abbility to trigger Push ("p" or blank OTP) and GriDsure ("g").

After successful  authentication, if a user has a single role assigned, an Access Token is generated and stored in .aws\credentials file. If the user has multiple roles assigned, the user is presented with the list of available roles to select the desired role and an Access Token is generated and stored.
