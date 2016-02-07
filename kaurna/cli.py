#!/usr/bin/env python

import argparse
import kaurna

class CLIDispatcher:

    operation_info={
        'create_kaurna_key':{
            'help':'Create the kaurna KMS key and key alias.  This must be called before kaurna can be used.  Because creating KMS keys is a non-reversible operation, this must be done manually.',
            'initial':'c'
            },
        'list_secrets':{
            'help':'List the stored secrets.  If you provide --secret-name, only versions of that secret will be shown.  If you provide --secret-name and --secret-version, only the one secret/version will be shown.',
            'initial':'l'
            },
        'rotate_keys':{
            'help':'Rotate the data keys used for the provided secret, or for all secrets if no secret name is provided.',
            'initial':'r'
            },
        'store_secret':{
            'help':'Store a new secret.',
            'initial':'s'
            },
        'erase_secret':{
            'help':'Erase the provided secret from kaurna.  Can be used to delete all versions of a secret, but cannot be used to delete all secrets at once.  For that, use --delete-all-the-things.',
            'initial':'e'
            },
        'deprecate_secrets':{
            'help':'Mark the provided secret as deprecated to prevent automated usage.',
            'initial':'d'
            },
        'activate_secrets':{
            'help':'Mark the provided secret as active to allow automated usage.',
            'initial':'a'
            },
        'update_secrets':{
            'help':'Update the list of entities allowed to access a secret, and rotate the data key.',
            'initial':'u'
            },
        'get_secret':{
            'help':'Download the desired secret.  This will print it to stdout; if you don\'t want it to appear on the screen, you can pipe the output of this command to a file or to a clipboard program like pbcopy or xclip (which one to use varies based on your OS).',
            'initial':'g'
            },
        'erase_all_the_things':{
            'help':'Erase every secret.  Only use this as a last resort.  Even if you pass in --force, this will require a prompt.',
            'initial':None
            }
        }
    
    def list_secrets(self, **kwargs):
        secrets = kaurna.describe_secrets(secret_name=kwargs['secret_name'], secret_version=kwargs['secret_version'], region=kwargs['region'])
        for secret in secrets.keys():
            print('Secret name: {0}'.format(secret))
            for version in secrets[secret].keys():
                print('  Version: {0}'.format(version))
                print('    Authorized entities:    {0}'.format(', '.join(secrets[secret][version]['authorized_entities']) if secrets[secret][version]['authorized_entities'] else '[None]'))
                print('    Deprecated:             {0}'.format('Yes' if secrets[secret][version]['deprecated'] else 'No'))
                print('    Created:                {0}'.format(secrets[secret][version]['create_date']))
                print('    Last data key rotation: {0}'.format(secrets[secret][version]['last_data_key_rotation']))
    
    def rotate_keys(self, **kwargs):
        kaurna.rotate_data_keys(**kwargs)
    
    def store_secret(self, **kwargs):
        kaurna.store_secret(**kwargs)
    
    def create_kaurna_key(self, **kwargs):
        print('About to create the kaurna KMS key.')
        if kwargs['force']:
            print('--force provided.  Skipping prompt.')
        else:
            response = raw_input('Proceed? Y/N ')
            if response.strip().lower() not in ['y','yes']:
                print('Aborted.')
                exit(1)
        if kaurna.create_kaurna_key(**kwargs):
            print('KMS key with alias \'kaurna\' created.')
        else:
            print('KMS key with alias \'kaurna\' already exists.  No need to create.')

    def erase_secret(self, **kwargs):
        if not kwargs['secret_name']:
            print('Must provide secret_name.')
            exit(1)
        print('About to delete the following secrets:')
        secrets = kaurna.load_all_entries(attributes_to_get=['secret_name','secret_version'], **kwargs)
        for secret in sorted(secrets, key=lambda s: '{0}/{1}'.format(s['secret_name'], s['secret_version'])):
            print('Name: {0}, version {1}'.format(secret['secret_name'], secret['secret_version']))
        if kwargs['force']:
            print('--force provided.  Skipping prompt.')
        else:
            response = raw_input('Y/N? ')
            if response.strip().lower() not in ['y','yes']:
                print('Aborted.')
                exit(1)
        kaurna.erase_secret(**kwargs)
    
    # hasn't yet been manually tested in its latest form
    def deprecate_secrets(self, **kwargs):
        secrets = kaurna.load_all_entries(attributes_to_get=['secret_name','secret_version','deprecated'], **kwargs)
        sorted_secrets = sorted([secret for secret in secrets if not secret['deprecated']], key=lambda s: '{0}/{1}'.format(s['secret_name'], s['secret_version']))
        if sorted_secrets:
            print('About to deprecate the following secrets:')
            for secret in sorted_secrets:
                print('Name: {0}, version {1}'.format(secret['secret_name'], secret['secret_version']))
            if kwargs['force']:
                print('--force provided.  Skipping prompt.')
            else:
                response = raw_input('Y/N? ')
                if response.strip().lower() not in ['y','yes']:
                    print('Aborted.')
                    exit(1)
            kaurna.deprecate_secrets(**kwargs)
        else:
            print('No active secrets matching those parameters found.')

    def activate_secrets(self, **kwargs):
        kaurna.activate_secrets(**kwargs)
    
    def update_secrets(self, **kwargs):
        kaurna.update_secrets(**kwargs)
    
    def get_secret(self, **kwargs):
        print(kaurna.get_secret(**kwargs))
    
    def erase_all_the_things(self, **kwargs):
        seriously=False
        print('YOU ARE ABOUT TO DELETE THE KAURNA DYNAMODB TABLE.  THIS WILL DELETE EVERYTHING.')
        print('Are you really sure you want to do this?')
        response = raw_input('Y/N? ')
        if response.strip().lower() not in ['y','yes']:
            print('Aborted.')
            exit(1)
        response2 = raw_input('Seriously? Y/N ')
        if response2.strip().lower() not in ['y','yes']:
            print('Aborted.')
            exit(1)
        else:
            seriously=True
        kaurna.erase_all_the_things(seriously=seriously, **kwargs)
        exit(1)

    def get_argument_parser(self):
        parser = argparse.ArgumentParser(description='Interact with kaurna from the command line.')
        operations = parser.add_mutually_exclusive_group(required=True)

        for operation in self.operation_info.keys():
            op = self.operation_info[operation]
            operation_cli = '--{0}'.format(operation.replace('_','-'))
            if op['initial']:
                operations.add_argument('-{0}'.format(op['initial']), operation_cli, action='store_true', help='Operation: {0}'.format(op['help']))
            else:
                operations.add_argument(operation_cli, action='store_true', help='Operation: {0}'.format(op['help']))

        parser.add_argument('--region', default='us-east-1', help='Argument: The AWS region to use.')
        parser.add_argument('--secret-name', default=None, help='Argument: The name of the secret.  Required for erase-secret, store-secret, and get-secret.  Optional for list-secrets, rotate-keys, deprecate-secrets, activate-secrets, and update-secrets.')
        parser.add_argument('--secret-version', default=None, help='Argument: The version of the secret to use.  If this is provided, secret-name must also be provided.  Optional for list-secrets, rotate-keys, store-secret, erase-secrets, deprecate-secrets, activate-secrets, update-secrets, and get-secret.')
        parser.add_argument('--secret', default=None, help='Argument: The secret to store.  Currently the only way to enter it is here, but I\'ll add a way to enter it that doesn\'t display it later.  Required for store-secret.')
        parser.add_argument('--authorized-entities', nargs='+', help='Argument: The entities that should have permission to access the secret(s).  Optional for update-secrets and store-secret; if not provided the empty list will be used.')
        parser.add_argument('-f', '--force', action='store_true', help='Argument: Skip normal confirmation prompts.  Optional for all calls.  Ignored by erase-all-the-things.')
        parser.add_argument('-v', '--verbose', action='store_true', help='Argument: Print random usually-useless information.  May or may not print anything depending on whether or not I\'ve implemented it yet, as I haven\'t right now.  Optional for all calls.')

        return parser

    def handle_args(self, args):
        operation = None
        argdict = {}
        for pair in args._get_kwargs():
            if pair[0] in self.operation_info.keys():
                operation = operation if not pair[1] else pair[0]
            else:
                argdict[pair[0]] = pair[1]
        try:
            getattr(self, operation)(**argdict)
        except Exception as e:
            print(e.message)
            exit(1)

    def do_stuff(self):
        parser = self.get_argument_parser()
        args = parser.parse_args()
        self.handle_args(args)
