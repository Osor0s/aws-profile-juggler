#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import logging
import sys

AWS_ACCESS_KEY_ID_ALIASES = ["aws_access_key_id","aws_access_key","aws_key","access_key","aws_key_id","access_key_id"] # always 20 chars
AWS_SECRET_ACCESS_KEY_ALIASES = ["aws_secret_key_id","aws_secret_key","secret_key","secret_key_id","aws_secret_access_key","secret_key_id"] # always 40 chars
AWS_SESSION_TOKEN_ALIASES = ["aws_session_token","aws_token","session_token","token"] # different lengths 876, 1160 , 876, 872
SEPERATORS = [" ",".","_","-","\-","\_","\ "]

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
    parser.add_argument("-p","--profile", help="profile name", type=str)
    parser.add_argument("-o","--overwrite", help="overwrite the profile entry if it exists", action="store_true")

    args = parser.parse_args()  

    # Setup loggin
    ## set logging level
    if args.verbose:
        log_level = logging.INFO
    elif args.debug:
        log_level = logging.DEBUG
    elif args.quite:
        log_level = logging.ERROR
    else:
        log_level = logging.WARNING
    ## initiate logger
    logging.basicConfig(filename='aws-profile-juggler.log',format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S', encoding='utf-8', level=log_level)
    logger = logging.getLogger('default_logger')
    logger.addHandler(logging.StreamHandler())

    credentials = {}
    # read pipe input
    if not sys.stdin.isatty():
        pipe_input = sys.stdin.read()
        logging.debug("Pipe input:")
        logging.debug(pipe_input)
        extract_credentials(pipe_input,credentials)


def extract_credentials(pipe_input,credentials):
    
    # find starting point of aws_access_key_id
    aws_access_key_id_start = -1
    AWS_ACCESS_KEY_ID_ALIASES
    for alias in AWS_ACCESS_KEY_ID_ALIASES:

    pass


def print_credentials(credentials):
    """
    Prints credential directory as three lines in export (linux) format
    """
    print(f'export AWS_ACCESS_KEY_ID="{credentials["aws_access_key_id"]}"\nexport AWS_SECRET_ACCESS_KEY="{credentials["aws_secret_access_key"]}"')
    if "aws_session_token" in credentials.keys() or credentials["aws_session_token"]=="":
        print(f'export AWS_SESSION_TOKEN="{credentials["aws_session_token"]}"')

if __name__ == "__main__":
    main()