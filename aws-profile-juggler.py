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

def main():


    # Parsing Options
    parser = argparse.ArgumentParser(description="Tool to perform different actions on AWS IAM profiles.")
    ## verbositiy
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--verbose", help="see additional output", action="store_true")
    group.add_argument("-q", "--quite", help="surpress all output", action="store_true")
    group.add_argument("-d", "--debug", help="See debug output", action="store_true")
    ## dealing with credentials
    parser.add_argument("--print-creds", help="print out the found credentials", action="store_true")
    parser.add_argument("-p","--profile", help="profile name", type=str,default="temp")
    parser.add_argument("-o","--overwrite", help="overwrite the profile entry if it exists", action="store_true")
    parser.add_argument("-f","--file",help = "AWS credentials file", type=str,default=AWS_CREDENTIALS_FILE)
    parser.add_argument("-c","--configure",help = "Configure (temp) AWS credentials manually", action="store_true")

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
    with open(file,'r+') as aws_credentials_file:
        file_content = aws_credentials_file.read()
        existing_entry_start = file_content.find(profile)

        if credentials['AWS_ACCESS_KEY_ID'].startswith("AKIA"):
            profile_string = f'[{profile}]\naws_access_key_id = {credentials["AWS_ACCESS_KEY_ID"]}\naws_secret_access_key={credentials["AWS_SECRET_ACCESS_KEY"]}'
        elif credentials['AWS_ACCESS_KEY_ID'].startswith("ASIA"):
            profile_string = f'[{profile}]\naws_access_key_id = {credentials["AWS_ACCESS_KEY_ID"]}\naws_secret_access_key={credentials["AWS_SECRET_ACCESS_KEY"]}\naws_session_token={credentials["AWS_SESSION_TOKEN"]}'
        else:
            print("[!] No valid AWS Access Key ID. Closing!")
            sys.exit(-1)

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

        aws_credentials_file.seek(0)
        aws_credentials_file.write(new_content)
        aws_credentials_file.truncate()

def configure_credentials(credentials, profile):
    print(f"Manually setting up profile as profile: {profile}")
    credentials["AWS_ACCESS_KEY_ID"] =      input("AWS Access Key ID: ")
    credentials["AWS_SECRET_ACCESS_KEY"] =  input("AWS Secret Access Key: ")
    if credentials["AWS_ACCESS_KEY_ID"].startswith("ASIA"):
        print(f"Recognised temporary credentials")
        credentials["AWS_SESSION_TOKEN"] =  input("AWS Session Token: ")

if __name__ == "__main__":
    main()