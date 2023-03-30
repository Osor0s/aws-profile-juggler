# AWSProfileJuggler
- when used as pipe part
   * (read the incoming stream)
   * (filter out awsaccesskey, accesskey, aws_access, aws-key, aws-access-key-id with all permutations of capitilasation )
    * (skip next characters until AKIA or ASIA start)
   * (read all signs of the access-key
        ? check if always a set amount of chars)
   * (check for secrect-key, secret_access_key, awssecretaccesskey in all capitalisations)
    * (skip next characters until secret-key starts
      ? check if always same length)
    * option to set customer search phrases
   * (if access-key found in input ASIA, search for token, session.token, AWS session token, AWS/-token)
   * (skip next sign until start of session token)
   * (read session token
   ? find out if set amount of chars for session token, checksum or byte length)
   * --show : prints out the credentials as profil-print and exportable Linux and exportable Powershell
   * (--profil <Profilname> write to creds file as new profile, warn if already exists, show overwrite option and print instead)
   * (--overwrite : overwrite existing profil, leave config (warn about this with print))
   * allow setting own search terms for different parts
-- quite : remove all informational printouts
## future
(-- add-mfa-role : ask for all required items to setup an MFA required role)
   * (MFA device id)
   * (target-role name)
   * (start profile)
   * (profile-name if not given as option already)
   * print out resulting config profile with random name
      ? check how docker chooses random names
   * like reading input warn if exists, suggest overwrite, overwrite if requested
- --list : list all profiles with their configs and whether or not they are temp credentials, MFA, long term
- -- get-caller-identity runs the command on the given profiles
   * if used with profile, runs on that profile or profiles
   * if use with input stream, will check the credentials right away, warning about detection and confirmation right away, while search already started. if no printout or overwrite  instead
   * if run without args, runs the command on all profiles, like list view but adds if valid
- encrypt/decrypt credential+config file
   * use standard AES256 lib