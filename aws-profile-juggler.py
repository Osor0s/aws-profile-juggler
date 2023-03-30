#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import logging
import sys
import re

from os import path

AWS_ACCESS_KEY_ID_ALIASES = ['accesskey', 'accesskeyid', 'awsaccesskeyid', 'awsaccesskey', 'aws access key id', 'aws.access.key.id', 'aws_access_key_id', 'aws-access-key-id', 'aws\-access\-key\-id', 'aws\_access\_key\_id', 'aws\ access\ key\ id', 'aws access key', 'aws.access.key', 'aws_access_key', 'aws-access-key', 'aws\-access\-key', 'aws\_access\_key', 'aws\ access\ key', 'aws key', 'aws.key', 'aws_key', 'aws-key', 'aws\-key', 'aws\_key', 'aws\ key', 'access key', 'access.key', 'access_key', 'access-key', 'access\-key', 'access\_key', 'access\ key', 'aws key id', 'aws.key.id', 'aws_key_id', 'aws-key-id', 'aws\-key\-id', 'aws\_key\_id', 'aws\ key\ id', 'access key id', 'access.key.id', 'access_key_id', 'access-key-id', 'access\-key\-id', 'access\_key\_id', 'access\ key\ id']
AWS_SECRET_ACCESS_KEY_ALIASES = ['secretaccesskey','awssecretaccesskey', 'secretkeyid','secretkey', 'awssecretkey','awssecretkeyid','aws secret key id', 'aws.secret.key.id', 'aws_secret_key_id', 'aws-secret-key-id', 'aws\-secret\-key\-id', 'aws\_secret\_key\_id', 'aws\ secret\ key\ id', 'aws secret key', 'aws.secret.key', 'aws_secret_key', 'aws-secret-key', 'aws\-secret\-key', 'aws\_secret\_key', 'aws\ secret\ key', 'secret key', 'secret.key', 'secret_key', 'secret-key', 'secret\-key', 'secret\_key', 'secret\ key', 'secret key id', 'secret.key.id', 'secret_key_id', 'secret-key-id', 'secret\-key\-id', 'secret\_key\_id', 'secret\ key\ id', 'aws secret access key', 'aws.secret.access.key', 'aws_secret_access_key', 'aws-secret-access-key', 'aws\-secret\-access\-key', 'aws\_secret\_access\_key', 'aws\ secret\ access\ key', 'secret key id', 'secret.key.id', 'secret_key_id', 'secret-key-id', 'secret\-key\-id', 'secret\_key\_id', 'secret\ key\ id']
AWS_SESSION_TOKEN_ALIASES = ['aws session token', 'aws.session.token', 'aws_session_token', 'aws-session-token', 'aws\-session\-token', 'aws\_session\_token', 'aws\ session\ token', 'aws token', 'aws.token', 'aws_token', 'aws-token', 'aws\-token', 'aws\_token', 'aws\ token', 'session token', 'session.token', 'session_token', 'session-token', 'session\-token', 'session\_token', 'session\ token', 'token']
#SEPERATORS = [" ",".","_","-","\-","\_","\ "]

AWS_CREDENTIALS_FILE = path.expanduser("~/.aws/credentials")
AWS_CONFIG_FILE = path.expanduser("~/.aws/config")

def main():


    # Parsing Options
    parser = argparse.ArgumentParser(description="Tool to perform different actions on AWS IAM profiles.")
    ## verbositiy
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--verbose", help="see additional output", action="store_true")
    group.add_argument("-q", "--quite", help="surpress all output", action="store_true")
    group.add_argument("-d", "--debug", help="See debug output", action="store_true")
    ## dealing with credentials
    parser.add_argument("--print-creds", help="additionally print out the found credentials to the commandline", action="store_true")
    parser.add_argument("-p","--profile", help="profile name", type=str,default="temp")
    parser.add_argument("-o","--overwrite", help="overwrite the profile entry if it exists", action="store_true")
    parser.add_argument("-f","--file",help = "AWS credentials file", type=str,default=AWS_CREDENTIALS_FILE)
    ## Options to configure credentials & profiles more easily
    parser.add_argument("-c","--configure",help = "Configure (temp) AWS credentials manually", action="store_true")
    parser.add_argument("-m","--mfa-configure",help = "Configure an mfa profile to automatically assume a role and ask for new token when necassary", action="store_true")
    parser.add_argument("--aws-config-file",help = "AWS config file", type=str,default=AWS_CONFIG_FILE)

    args = parser.parse_args()  

    # Setup loggin
    ## set logging level
    if args.verbose:
        log_level = logging.INFO
    elif args.quite:
        log_level = logging.ERROR
    elif args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING
    ## initiate logger
    logging.basicConfig(filename='aws-profile-juggler.log',format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S', encoding='utf-8', level=log_level)
    logger = logging.getLogger('default_logger')
    logger.addHandler(logging.StreamHandler())

    credentials = {}
    # read pipe input

    if args.configure:
        configure_credentials(credentials, args.profile)
        write_credentials(credentials, args.file, args.profile, args.overwrite)
        sys.exit(0)
    
    if args.mfa_configure:
        write_mfa_profile(args.profile,args.aws_config_file,args.overwrite)
        sys.exit(0)

    elif not sys.stdin.isatty():
        pipe_input = sys.stdin.read()
        logging.debug("Pipe input:")
        logging.debug(pipe_input)


        extract_credentials(pipe_input,credentials)

        if args.print_creds:
            print_credentials(credentials,args.profile)

        write_credentials(credentials, args.file, args.profile, args.overwrite)
    else:
        parser.print_help()

        


def extract_credentials(pipe_input,credentials):
    credentials["AWS_ACCESS_KEY_ID"]=""
    credentials["AWS_SECRET_ACCESS_KEY"]=""
    credentials["AWS_SESSION_TOKEN"]=""

    for credential_part in credentials.keys():
        if credential_part == "AWS_ACCESS_KEY_ID":
            pattern = r'[a-zA-Z0-9]{20}'
            aliases = AWS_ACCESS_KEY_ID_ALIASES
        elif credential_part == "AWS_SECRET_ACCESS_KEY":
            pattern = r'[a-zA-Z0-9/+]{40}'
            aliases = AWS_SECRET_ACCESS_KEY_ALIASES
        elif credential_part == "AWS_SESSION_TOKEN":
            pattern = r'[I][a-zA-Z0-9/+=]{200,}'
            aliases = AWS_SESSION_TOKEN_ALIASES

        for alias in aliases:
            credential_part_start = pipe_input.lower().find(alias)
            if credential_part_start != -1:
                #found credential part
                m = re.search(pattern,pipe_input[credential_part_start:])
                credentials[credential_part] = m.group(0)
                logging.debug(f'extracted {credential_part} = {credentials[credential_part]}')
                credential_part_start=-1
                break


def print_credentials(credentials,profile):
    """
    Prints credential directory as three lines in export (linux) format
    """
    if credentials['AWS_ACCESS_KEY_ID'].startswith("AKIA"):
        print(f'[{profile}]\naws_access_key_id = {credentials["AWS_ACCESS_KEY_ID"]}\naws_secret_access_key={credentials["AWS_SECRET_ACCESS_KEY"]}')
    else:
        print(f'[{profile}]\naws_access_key_id = {credentials["AWS_ACCESS_KEY_ID"]}\naws_secret_access_key={credentials["AWS_SECRET_ACCESS_KEY"]}\naws_session_token={credentials["AWS_SESSION_TOKEN"]}')



def write_credentials(credentials, file, profile, overwrite):
    """
    Writes the credentials to the ~/.aws/credentials file.
    """

    # create new profile with the credentials
    if credentials['AWS_ACCESS_KEY_ID'].startswith("AKIA"):
        profile_string = f'[{profile}]\naws_access_key_id = {credentials["AWS_ACCESS_KEY_ID"]}\naws_secret_access_key = {credentials["AWS_SECRET_ACCESS_KEY"]}'
    elif credentials['AWS_ACCESS_KEY_ID'].startswith("ASIA"):
        profile_string = f'[{profile}]\naws_access_key_id = {credentials["AWS_ACCESS_KEY_ID"]}\naws_secret_access_key = {credentials["AWS_SECRET_ACCESS_KEY"]}\naws_session_token = {credentials["AWS_SESSION_TOKEN"]}'
    else:
        print("[!] No valid AWS Access Key ID. Closing!")
        sys.exit(-1)

    write_new_profile(profile_string, file, profile, overwrite)
    

def write_new_profile(profile_string, file, profile_start_string, overwrite):
    # find position for the profile
    with open(file,'r+') as aws_file:
        file_content = aws_file.read()
        existing_entry_start = file_content.find(profile_start_string)

        if existing_entry_start == -1:
            #add new profile if name does not exist
            new_content = file_content +"\n"+ profile_string
        else:
            if not overwrite:
                print('[!] Profile already exists! Either choose a different profile name with the option "-p" OR use "-o" to overwrite the existing profile')
                return
            else:
                distance_to_next_profile = file_content[existing_entry_start:].find("[")
                if distance_to_next_profile == -1:
                    new_content = file_content[:existing_entry_start-1]+profile_string
                else:
                    new_content =file_content[:existing_entry_start-1]+profile_string+"\n"+file_content[existing_entry_start+distance_to_next_profile:]

        aws_file.seek(0)
        aws_file.write(new_content)
        aws_file.truncate()



def configure_credentials(credentials, profile):
    print(f"Manually setting up aws credentials as profile: {profile}")
    credentials["AWS_ACCESS_KEY_ID"] = input("AWS Access Key ID: ")
    credentials["AWS_SECRET_ACCESS_KEY"] = input("AWS Secret Access Key: ")
    if credentials["AWS_ACCESS_KEY_ID"].startswith("ASIA"):
        print(f"Recognised temporary credentials")
        credentials["AWS_SESSION_TOKEN"] = input("AWS Session Token: ")


def write_mfa_profile(profile, file, overwrite):
    print(f"Manually setting up an MFA profile with the name: {profile}")
    # Take necessary values for the profile from the user
    mfa_serial = input("ARN of the MFA device: ")
    source_profile = input("Profile which is allowed to assume the role: ")
    role_session_name = input(f"Define a custom 'role session name' (default: {profile}): ")
    if role_session_name == "":
        role_session_name = profile
    role_arn = input(f"Assumeable role which requires MFA: ")

    #prepare profile string and write it to the file
    profile_string = f"[profile {profile}]\nmfa_serial = {mfa_serial}\nsource_profile = {source_profile}\nrole_session_name = {role_session_name}\nrole_arn = {role_arn}"
    profile_start_string = f"profile {profile}"
    write_new_profile(profile_string, file, profile_start_string, overwrite)

if __name__ == "__main__":
    main()