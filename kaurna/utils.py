#!/usr/bin/env python

import base64
import boto.dynamodb
import boto.kms
from Crypto.Cipher import AES
from Crypto import Random

# http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
BS = 16
# this appends BS - len(s) % BS (that is, the lowest number >0 that can be added to len(s) to get a multiple of BS) bytes to s,
# where each byte is the number of bytes to be appended
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
# this removes the last X bytes of s, where X is the numeric value of the last byte
unpad = lambda s: s[:-ord(s[len(s)-1:])]

def get_kaurna_table(create_if_missing=True, region='us-east-1'):
    # This method will get the DynamoDB table object and return it.
    pass

def create_kaurna_table(region='us-east-1'):
    # This method will create the kaurna table.
    # schema:
    # hash: secret_name
    # range: secret_version
    # encrypted_secret
    # encrypted_data_key
    # encryption_context
    # authorized_entities
    # create_date
    # last_data_key_rotation
    pass

def create_kaurna_key(region='us-east-1'):
    # This method will create the kaurna KMS master key if necessary
    kms = boto.kms.connect_to_region(region_name=region)
    # list_aliases response:
    # {'Truncated': False, 'Aliases': [{'AliasArn': 'arn:aws:kms:us-east-1:000000000000:alias/aws/ebs', 'AliasName': 'alias/aws/ebs'}, {'AliasArn': 'arn:aws:kms:us-east-1:000000000000:alias/aws/rds', 'AliasName': 'alias/aws/rds'}, {'AliasArn': 'arn:aws:kms:us-east-1:000000000000:alias/aws/redshift', 'AliasName': 'alias/aws/redshift'}, {'AliasArn': 'arn:aws:kms:us-east-1:000000000000:alias/aws/s3', 'AliasName': 'alias/aws/s3'}, {'AliasArn': 'arn:aws:kms:us-east-1:000000000000:alias/kaurna', 'AliasName': 'alias/kaurna', 'TargetKeyId': '1234abcd-12ab-12ab-12ab-123456abcdef'}]}
    aliases = kms.list_aliases()
    if 'alias/kaurna' in [alias['AliasName'] for alias in aliases['Aliases']]:
        return
    else:
        # create_key response:
        # {'KeyMetadata': {'KeyId': '1234abcd-12ab-12ab-12ab-123456abcdef', 'Description': '', 'Enabled': True, 'KeyUsage': 'ENCRYPT_DECRYPT', 'CreationDate': 1431872957.123, 'Arn': 'arn:aws:kms:us-east-1:000000000000:key/1234abcd-12ab-12ab-12ab-123456abcdef', 'AWSAccountId': '000000000000'}}
        # TODO: see what the format of this response is and make it so that the alias gets attached properly
        response = kms.create_key()
        # create_alias has no output
        kms.create_alias('alias/kaurna', response['KeyMetadata']['KeyId'])
        return

def get_data_key(encryption_context=None, region='us-east-1'):
    # This method will generate a new data key
    kms = boto.kms.connect_to_region(region_name=region)
    # generate_data_key output:
    # {'Plaintext': '<binary blob>', 'KeyId': 'arn:aws:kms:us-east-1:000000000000:key/1234abcd-12ab-12ab-12ab-123456abcdef', 'CiphertextBlob': '<binary blob>'}
    data_key = kms.generate_data_key(key_id='alias/kaurna', encryption_context=encryption_context, key_spec='AES_256')
    return data_key

def store_secret(secret_name, secret, version=1, authorized_entities=None, region='us-east-1'):
    # This method will store the key in DynamoDB
    pass

def rotate_data_key(secret_name, version=None, region='us-east-1'):
    # This method will rotate the data key on a secret/version pair, or all versions of a secret if version is None

    encrypted_secret = 'foo'
    encrypted_key='bar'
    encryption_context='{"foo":"bar"}'
    # Let's assume the correct row has been loaded so that I can write the KMS part now
    decrypted_key = decrypt_with_kms(encrypted_key, encryption_context, region=region)['Plaintext']
    decrypted_secret = decrypt_with_key(encrypted_secret, decrypted_key)
    new_data_key = get_data_key(encryption_context=encryption_context, region=region)
    new_encrypted_key = binascii.b2a_base64(new_data_key['CiphertextBlob'])
    new_encrypted_secret = encrypt_with_key(plaintext=decrypted_secret, key=new_data_key['Plaintext'])
    # store new_encrypted_key and new_encrypted_secret in DynamoDB
    pass

def update_secret(secret_name, version=None, authorized_entities=None, region='us-east-1'):
    # This method will update the authorized entities for a secret.
    # If no version is specified, it will update all versions of the secret
    pass

def delete_secret(secret_name, version=None, region='us-east-1'):
    # This method will delete the specified secret, or all versions of the secret if version is None
    pass

def list_secrets(region='us-east-1'):
    # This method will list all of the stored secrets
    pass

def describe_secret(secret_name, version=None, region='us-east-1'):
    # This method will return a variety of non-secret information about a secret
    pass

def get_secret(secret_name, version=None, region='us-east-1'):
    # Load the possible rows from DynamoDB
    # If the version is specified, we know specifically which entry to load.
    # If the version isn't specified, load the highest-numbered one.
    # Or perhaps they'll all be stored in the same entry, who knows.
    # Pull the ciphertext and encryption context
    # Decrypt with KMS
    # Profit
    encrypted_secret = 'foo'
    encrypted_key='bar'
    encryption_context='{"foo":"bar"}'
    # Let's assume the correct row has been loaded so that I can write the KMS part now
    decrypted_key = decrypt_with_kms(encrypted_key, encryption_context)['Plaintext']
    decrypted_secret = decrypt_with_key(encrypted_secret, decrypted_key)
    return decrypted_secret

def encrypt_with_key(plaintext, key, iv=None):
    return (lambda iv: base64.b64encode(iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext))))(iv if iv else Random.new().read(AES.block_size))

def decrypt_with_key(ciphertext, key):
    return unpad(AES.new(key, AES.MODE_CBC, base64.b64decode(ciphertext)[:16]).decrypt(base64.b64decode(ciphertext)[16:]))

def encrypt_with_kms(plaintext, key_id='alias/kaurna', encryption_context=None, grant_tokens=None, region='us-east-1'):
    # encrypt output:
    # {u'KeyId': u'arn:aws:kms:us-east-1:000000000000:key/1234abcd-12ab-12ab-12ab-123456abcdef', u'CiphertextBlob': '<binary blob>'}
    return binascii.b2a_base64(boto.kms.conenct_to_region(region_name=region).encrypt(key_id=key_id, plaintext=plaintext, encryption_context=encryption_context, grant_tokens=grant_tokens)['CiphertextBlob'])

def decrypt_with_kms(ciphertext_blob, encryption_context=None, grant_tokens=None, region='us-east-1'):
    # decrypt output:
    # {'Plaintext': '<binary blob>', 'KeyId': 'arn:aws:kms:us-east-1:000000000000:key/1234abcd-12ab-12ab-12ab-123456abcdef'}
    return boto.kms.connect_to_region(region_name=region).decrypt(ciphertext_blob = binascii.a2b_base64(ciphertext_blob), encryption_context=encryption_context, grant_tokens=grant_tokens)

