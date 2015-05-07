#!/usr/bin/env python

# This file will contain the general kaurna functionality needed by both kaurna.writer and kaurna.reader.

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

def encrypt_with_key(plaintext, key, iv=None):
    return (lambda iv: base64.b64encode(iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext))))(iv if iv else Random.new().read(AES.block_size))

def decrypt_with_key(ciphertext, key):
    return unpad(AES.new(key, AES.MODE_CBC, base64.b64decode(ciphertext)[:16]).decrypt(base64.b64decode(ciphertext)[16:]))

def encrypt_with_kms(plaintext, key_id, encryption_context=None, grant_tokens=None, region='us-east-1'):
    return binascii.b2a_base64(boto.kms.conenct_to_region(region_name=region).encrypt(key_id=key_id, plaintext=plaintext, encryption_context=encryption_context, grant_tokens=grant_tokens)['CiphertextBlob'])

def decrypt_with_kms(ciphertext_blob, encryption_context=None, grant_tokens=None, region='us-east-1'):
    return boto.kms.conenct_to_region(region_name=region).decrypt(ciphertext_blob = binascii.a2b_base64(ciphertext_blob), encryption_context=encryption_context, grant_tokens=grant_tokens)

def download_secret(secret_name, version=None, region='us-east-1'):
    # Load the possible rows from DynamoDB
    # If the version is specified, we know specifically which entry to load.
    # If the version isn't specified, load the highest-numbered one.
    # Or perhaps they'll all be stored in the same entry, who knows.
    # Pull the ciphertext and encryption context
    # Decrypt with KMS
    # Profit
    pass

def upload_secret(secret_name, secret, encryption_context=None, version=None, region='us-east-1'):
    pass
