# aws-profile-juggler
## TL;DR
Easily interact with AWS profiles. Helps with ...
- extratcing AWS (temp) credentials from input in multiple typical formats
- add credentials as profiles to the aws credential file  (`~/.aws/credentials`)
- configure a set of credentials manually INCLUDING temporary credentials
- configure a profile for an assumeable role which requires MFA

## Usage
```
usage: aws-profile-juggler.py [-h] [-v | -q | -d] [--print-creds] [-p PROFILE] [-o] [-f FILE] [-c] [-m] [--aws-config-file AWS_CONFIG_FILE]

Tool to perform different actions on AWS IAM profiles.

options:
  -h, --help            show this help message and exit
  -v, --verbose         see additional output
  -q, --quite           surpress all output
  -d, --debug           See debug output
  --print-creds         additionally print out the found credentials to the commandline
  -p PROFILE, --profile PROFILE
                        profile name
  -o, --overwrite       overwrite the profile entry if it exists
  -f FILE, --file FILE  AWS credentials file
  -c, --configure       Configure (temp) AWS credentials manually
  -m, --mfa-configure   Configure an mfa profile to automatically assume a role and ask for new token when necassary
  --aws-config-file AWS_CONFIG_FILE
```
### Automatically extract (temporary) AWS credentials from input and add it to your aws credential file (`~/.aws/credentials`)
Extract credentials from the input file and save them as $PROFILE_NAME (Overwrite an existing profile with the same name)
```console
$ cat input | python3 aws-profile-juggler.py --profile $PROFILE_NAME --overwrite 
```
#### Example
Example output from IMDS:
```console
$ curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
{
        "Type": "",
        "AccessKeyId": "ASIAABCDEFGHIJKLMNOP",
        "SecretAccessKey": "1ruD8FcVL7AdKh7XVXjWsNqx0LYorVTZCA9ysJVB",
        "Token": "FzwzjCskALu0..ds97d3n3FSK3DM==",
        "Expiration": "2099-03-30T00:00:00Z",
        "Code": "Success"
}
```

Pipe the output straight into the tool
```console
$ curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/ | python3 aws-profile-juggler.py -p $PROFILE_NAME -o  
```

### Configure a set of credentials manually INCLUDING temporary credentials
Add temporary credentials manually without having to edit the credentials file
```console
$ ./aws-profile-juggler.py --configure --profile $PROFILE_NAME
Manually setting up aws credentials as profile: temporary-credentials
AWS Access Key ID: ASIAABCDEFGHIJKLMNOP
AWS Secret Access Key: 1ruD8FcVL7AdKh7XVXjWsNqx0LYorVTZCA9ysJVB
Recognised temporary credentials
AWS Session Token: FzwzjCskALu0...ds97d3n3FSK3DM==
```

### Configure a profile for an assumeable role which requires MFA
When working with roles which require MFA tokens. AWS offers the option to setup a profile in the config file which automatically asks for new OTPs if the old session is no longer active. The following helps you set that up

```console
$ ./aws-profile-juggler.py --mfa-configure --profile $PROFILE_NAME
Manually setting up an MFA profile with the name: mfa-role
ARN of the MFA device: arn:aws:iam::<account_number>:mfa/<user_name>
Profile which is allowed to assume the role: <source_profile>
Define a custom 'role session name' (default: <profile_for_user_name>): <session_name>
Arn of assumeable role which requires MFA: arn:aws:iam::<account_number_for_role>:role/<role_name>
```
