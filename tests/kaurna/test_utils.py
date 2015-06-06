#!/usr/bin/env python

from boto.dynamodb.condition import EQ
from boto.exception import DynamoDBResponseError
from kaurna.utils import *
import kaurna.utils # necessary to test _generate_encryption_context
from mock import call, MagicMock, Mock, patch
from nose.tools import assert_equals, raises
from unittest import TestCase

# http://www.openp2p.com/pub/a/python/2004/12/02/tdd_pyunit.html

class KaurnaUtilsTests(TestCase):

    def setUp(self):
        self.mock_kms = MagicMock()
        patch('kaurna.utils.boto.kms.connect_to_region', Mock(return_value=self.mock_kms)).start()

        self.mock_ddb = MagicMock()
        patch('kaurna.utils.boto.dynamodb.connect_to_region', Mock(return_value=self.mock_ddb)).start()

    def tearDown(self):
        patch.stopall()

    def test_GIVEN_kaurna_table_doesnt_exist_WHEN_get_kaurna_table_called_THEN_table_created_and_returned(self):
        # GIVEN - set up mocks
        self.mock_ddb.get_table.side_effect = [DynamoDBResponseError('Foo','Bar')]

        mock_table = MagicMock()
        self.mock_ddb.create_table.return_value = mock_table

        mock_schema = MagicMock()
        self.mock_ddb.create_schema.return_value = mock_schema

        # WHEN - perform the actions under test
        returned_table = get_kaurna_table(region='us-east-1', read_throughput=5, write_throughput=2)

        # THEN - verify the expected results were observed
        assert_equals(mock_table, returned_table)
        assert_equals(
            self.mock_ddb.create_table.call_args_list,
            [call(name='kaurna', schema=mock_schema, read_units=5, write_units=2)]
            )

    def test_GIVEN_kaurna_table_exists_WHEN_get_kaurna_table_called_THEN_table_returned(self):
        # GIVEN - set up mocks
        mock_table = MagicMock()
        self.mock_ddb.get_table.return_value = mock_table

        # WHEN - perform the actions under test
        returned_table = get_kaurna_table(region='us-east-1', read_throughput=5, write_throughput=2)

        # THEN - verify the expected results were observed
        assert_equals(mock_table, returned_table)
        assert_equals(
            self.mock_ddb.create_table.call_args_list,
            []
            )

    def test_GIVEN_kaurna_key_doesnt_exist_WHEN_create_kaurna_key_called_THEN_kaurna_key_created(self):
        # GIVEN
        self.mock_kms.list_aliases.return_value = {'Aliases':[
                {'AliasArn': 'arn:aws:kms:us-east-1:000000000000:alias/aws/ebs', 'AliasName': 'alias/aws/ebs'},
                {'AliasArn': 'arn:aws:kms:us-east-1:000000000000:alias/aws/redshift', 'AliasName': 'alias/aws/redshift'},
                {'AliasArn': 'arn:aws:kms:us-east-1:000000000000:alias/aws/s3', 'AliasName': 'alias/aws/s3'},
                ]}
        self.mock_kms.create_key.return_value = {'KeyMetadata':{'KeyId':'foobar'}}

        # WHEN
        create_kaurna_key()

        # THEN
        assert_equals(
            self.mock_kms.create_key.call_args_list,
            [call()]
            )
        assert_equals(
            self.mock_kms.create_alias.call_args_list,
            [call('alias/kaurna', 'foobar')]
            )

    def test_GIVEN_kaurna_key_exists_WHEN_create_kaurna_key_called_THEN_nothing_happens(self):
        # GIVEN
        self.mock_kms.list_aliases.return_value = {'Aliases':[
                {'AliasArn': 'arn:aws:kms:us-east-1:000000000000:alias/aws/ebs', 'AliasName': 'alias/aws/ebs'},
                {'AliasArn': 'arn:aws:kms:us-east-1:000000000000:alias/aws/redshift', 'AliasName': 'alias/aws/redshift'},
                {'AliasArn': 'arn:aws:kms:us-east-1:000000000000:alias/aws/s3', 'AliasName': 'alias/aws/s3'},
                {'AliasArn': 'arn:aws:kms:us-east-1:000000000000:alias/kaurna', 'AliasName': 'alias/kaurna'},
                ]}

        # WHEN
        create_kaurna_key()

        # THEN
        assert_equals(
            self.mock_kms.create_key.call_args_list,
            []
            )
        assert_equals(
            self.mock_kms.create_alias.call_args_list,
            []
            )

    def test_WHEN_get_data_key_called_THEN_kaurna_key_created_and_data_key_generated(self):
        # GIVEN
        expected_data_key = {'Plaintext': '<binary blob>', 'KeyId': 'arn:aws:kms:us-east-1:000000000000:key/1234abcd-12ab-12ab-12ab-123456abcdef', 'CiphertextBlob': '<binary blob>'}
        self.mock_kms.generate_data_key.return_value = expected_data_key

        encryption_context = {'hafgufa':'kaurna','edofleini':'kaurna'}

        # WHEN
        actual_data_key = get_data_key(encryption_context=encryption_context)

        # THEN
        assert_equals(
            expected_data_key,
            actual_data_key
            )
        assert_equals(
            self.mock_kms.generate_data_key.call_args_list,
            [call(key_id='alias/kaurna', encryption_context=encryption_context, key_spec='AES_256')]
            )

    # Don't really need to test; it's an entirely internal method with no network calls.
    # It's covered by other tests, but testing it separately makes it easy to pinpoint if it ever gets broken.
    def test_WHEN__generate_encryption_context_called_THEN_proper_encryption_context_generated(self):
        # GIVEN
        expected_encryption_context = {'hafgufa':'kaurna','edofleini':'kaurna'}
        authorized_entities = ['hafgufa','edofleini']

        # WHEN
        actual_encryption_context = kaurna.utils._generate_encryption_context(authorized_entities=authorized_entities)

        # THEN
        assert_equals(
            expected_encryption_context,
            actual_encryption_context
            )

    @raises(Exception)
    def test_GIVEN_secret_not_provided_WHEN_store_secret_called_THEN_error_thrown(self):
        # GIVEN
        secret = None
        secret_name = 'password'
        secret_version = None
        authorized_entities = ['Sterling Archer', 'Cyril Figgis']

        # WHEN
        store_secret(secret=secret, secret_name=secret_name, secret_version=secret_version, authorized_entities=authorized_entities)

        # THEN
        # Exception should get thrown and we should never get here

    @raises(Exception)
    def test_GIVEN_secret_name_not_provided_WHEN_store_secret_called_THEN_error_thrown(self):
        # GIVEN
        secret = 'guest'
        secret_name = None
        secret_version = None
        authorized_entities = ['Sterling Archer', 'Cyril Figgis']

        # WHEN
        store_secret(secret=secret, secret_name=secret_name, secret_version=secret_version, authorized_entities=authorized_entities)

        # THEN
        # Exception should get thrown and we should never get here

    @raises(Exception)
    def test_GIVEN_secret_version_exists_WHEN_store_secret_called_THEN_error_thrown(self):
        # GIVEN
        secret = 'guest'
        secret_name = 'password'
        secret_version = 3
        authorized_entities = ['Sterling Archer', 'Cyril Figgis']

        patch(
            'kaurna.utils.load_all_entries',
            Mock(
                return_value = [
                    {'secret_name':'password','secret_version':3}
                    ]
                )
            ).start()

        # WHEN
        store_secret(secret=secret, secret_name=secret_name, secret_version=secret_version, authorized_entities=authorized_entities)

        # THEN
        # Exception should get thrown and we should never get here

    def test_GIVEN_secret_version_not_provided_WHEN_store_secret_called_THEN_secret_properly_stored(self):
        # GIVEN
        secret = 'guest'
        secret_name = 'password'
        secret_version = None
        authorized_entities = ['Sterling Archer', 'Cyril Figgis']

        patch(
            'kaurna.utils.load_all_entries',
            Mock(
                return_value = [
                    {'secret_name':'password','secret_version':1},
                    {'secret_name':'password','secret_version':2},
                    {'secret_name':'password','secret_version':4}
                    ]
                )
            ).start()

        patch('kaurna.utils.get_data_key', Mock(return_value={'CiphertextBlob':'abcdabcdabcdabcd','Plaintext':'1234123412341234'})).start()
        patch('kaurna.utils.encrypt_with_key', Mock(return_value='<insert encrypted stuff here>')).start()
        patch('kaurna.utils.time.time', Mock(return_value=1234.5678)).start()

        mock_table = MagicMock()
        patch('kaurna.utils.get_kaurna_table', Mock(return_value=mock_table)).start()

        mock_item = MagicMock()
        mock_table.new_item.return_value = mock_item

        expected_attributes = {
            'secret_name': secret_name,
            'secret_version': 5,
            'encrypted_secret': '<insert encrypted stuff here>',
            'encrypted_data_key': binascii.b2a_base64('abcdabcdabcdabcd'),
            'encryption_context': '{"Sterling Archer": "kaurna", "Cyril Figgis": "kaurna"}',
            'authorized_entities': json.dumps(authorized_entities),
            'create_date': 1234,
            'last_data_key_rotation': 1234,
            'deprecated': False
            }

        # WHEN
        store_secret(secret=secret, secret_name=secret_name, secret_version=secret_version, authorized_entities=authorized_entities)

        # THEN
        assert_equals(
            mock_table.new_item.call_args_list,
            [call(attrs=expected_attributes)]
            )
        assert_equals(
            mock_item.save.call_args_list,
            [call()]
            )

    def test_GIVEN_secret_version_provided_WHEN_store_secret_called_THEN_secret_properly_stored(self):
        # GIVEN
        secret = 'guest'
        secret_name = 'password'
        secret_version = 3
        authorized_entities = ['Sterling Archer', 'Cyril Figgis']

        patch(
            'kaurna.utils.load_all_entries',
            Mock(
                return_value = []
                )
            ).start()

        patch('kaurna.utils.get_data_key', Mock(return_value={'CiphertextBlob':'abcdabcdabcdabcd','Plaintext':'1234123412341234'})).start()
        patch('kaurna.utils.encrypt_with_key', Mock(return_value='<insert encrypted stuff here>')).start()
        patch('kaurna.utils.time.time', Mock(return_value=1234.5678)).start()

        mock_table = MagicMock()
        patch('kaurna.utils.get_kaurna_table', Mock(return_value=mock_table)).start()

        mock_item = MagicMock()
        mock_table.new_item.return_value = mock_item

        expected_attributes = {
            'secret_name': secret_name,
            'secret_version': 3,
            'encrypted_secret': '<insert encrypted stuff here>',
            'encrypted_data_key': binascii.b2a_base64('abcdabcdabcdabcd'),
            'encryption_context': '{"Sterling Archer": "kaurna", "Cyril Figgis": "kaurna"}',
            'authorized_entities': json.dumps(authorized_entities),
            'create_date': 1234,
            'last_data_key_rotation': 1234,
            'deprecated': False
            }

        # WHEN
        store_secret(secret=secret, secret_name=secret_name, secret_version=secret_version, authorized_entities=authorized_entities)

        # THEN
        assert_equals(
            mock_table.new_item.call_args_list,
            [call(attrs=expected_attributes)]
            )
        assert_equals(
            mock_item.save.call_args_list,
            [call()]
            )

    @raises(Exception)
    def test_GIVEN_secret_version_but_not_secret_name_provided_WHEN_load_all_entries_called_THEN_error_thrown(self):
        # GIVEN
        secret_name = None
        secret_version = 2

        # WHEN
        load_all_entries(secret_name=secret_name, secret_version=secret_version)

        # THEN
        # Exception should get thrown and we should never get here

    def test_GIVEN_secret_name_and_secret_version_provided_WHEN_load_all_entries_called_THEN_proper_dynamodb_call_made(self):
        # GIVEN
        secret_name = 'password'
        secret_version = 2
        attributes_to_get = ['secret_name', 'secret_version']

        mock_table = MagicMock()
        self.mock_ddb.get_table.return_value = mock_table
        expected_output = [
            {'secret_name':secret_name,'secret_version':secret_version}
            ]
        mock_table.query.return_value = expected_output

        # WHEN
        actual_output = load_all_entries(secret_name=secret_name, secret_version=secret_version, attributes_to_get=attributes_to_get)

        # THEN
        assert_equals(
            expected_output,
            actual_output
            )
        assert_equals(
            mock_table.query.call_args_list,
            [call(hash_key=secret_name, range_key_condition=EQ(int(secret_version)), attributes_to_get=attributes_to_get)]
            )

    def test_GIVEN_secret_name_but_not_secret_version_provided_WHEN_load_all_entries_called_THEN_proper_dynamodb_call_made(self):
        # GIVEN
        secret_name = 'password'
        secret_version = None
        attributes_to_get = ['secret_name', 'secret_version']

        mock_table = MagicMock()
        self.mock_ddb.get_table.return_value = mock_table
        expected_output = [
            {'secret_name':secret_name,'secret_version':1},
            {'secret_name':secret_name,'secret_version':2}
            ]
        mock_table.query.return_value = expected_output

        # WHEN
        actual_output = load_all_entries(secret_name=secret_name, secret_version=secret_version, attributes_to_get=attributes_to_get)

        # THEN
        assert_equals(
            expected_output,
            actual_output
            )
        assert_equals(
            mock_table.query.call_args_list,
            [call(hash_key=secret_name, attributes_to_get=attributes_to_get)]
            )

    def test_GIVEN_no_secret_information_provided_WHEN_load_all_entries_called_THEN_proper_dynamodb_call_made(self):
        # GIVEN
        secret_name = None
        secret_version = None
        attributes_to_get = ['secret_name', 'secret_version']

        mock_table = MagicMock()
        self.mock_ddb.get_table.return_value = mock_table
        expected_output = [
            {'secret_name':'password','secret_version':1},
            {'secret_name':'password','secret_version':2},
            {'secret_name':'private_key','secret_version':1},
            {'secret_name':'private_key','secret_version':2}
            ]
        mock_table.scan.return_value = expected_output

        # WHEN
        actual_output = load_all_entries(secret_name=secret_name, secret_version=secret_version, attributes_to_get=attributes_to_get)

        # THEN
        assert_equals(
            expected_output,
            actual_output
            )
        assert_equals(
            mock_table.scan.call_args_list,
            [call(attributes_to_get=attributes_to_get)]
            )

    def test_WHEN_rotate_data_keys_called_THEN_data_keys_rotated(self):
        self.fail()

    def test_WHEN__reencrypt_item_and_save_called_THEN_item_reencrypted_and_saved(self):
        self.fail()

    def test_WHEN_update_secrets_called_THEN_proper_secrets_updated(self):
        self.fail()

    @raises(Exception)
    def test_GIVEN_provided_secret_name_is_None_WHEN_erase_secret_called_THEN_error_thrown(self):
        # GIVEN
        secret_name = None
        secret_version = None

        # WHEN
        erase_secret(secret_name=secret_name, secret_version=secret_version)

        # THEN
        # Exception should get thrown and we should never get here

    def test_GIVEN_provided_secret_name_is_not_None_WHEN_erase_secret_called_THEN_proper_secret_erased(self):
        self.fail()

    def test_GIVEN_seriously_is_False_WHEN_erase_all_the_things_called_THEN_nothing_happens(self):
        self.fail()

    def test_GIVEN_seriously_is_True_WHEN_erase_all_the_things_called_THEN_kaurna_table_deleted(self):
        self.fail()

    def test_WHEN_deprecate_secrets_called_THEN_proper_secrets_deprecated(self):
        self.fail()

    def test_WHEN_activate_secrets_called_THEN_proper_secrets_activated(self):
        self.fail()

    def test_WHEN_describe_secrets_called_THEN_proper_descriptions_returned(self):
        self.fail()

    @raises(Exception)
    def test_GIVEN_provided_secret_name_is_None_WHEN_get_secret_called_THEN_error_thrown(self):
        # GIVEN
        secret_name = None
        secret_version = None

        # WHEN
        get_secret(secret_name=secret_name, secret_version=secret_version)

        # THEN
        # Exception should get thrown and we should never get here

    @raises(Exception)
    def test_GIVEN_secret_not_found_WHEN_get_secret_called_THEN_error_thrown(self):
        # GIVEN
        secret_name = 'password'
        secret_version = 3

        patch(
            'kaurna.utils.load_all_entries',
            Mock(
                return_value = []
                )
            ).start()

        # WHEN
        get_secret(secret_name=secret_name, secret_version=secret_version)

        # THEN
        # Exception should get thrown and we should never get here

    @raises(Exception)
    def test_GIVEN_all_secret_versions_are_deprecated_WHEN_get_secret_called_THEN_error_thrown(self):
        # GIVEN
        secret_name = 'password'
        secret_version = None

        patch(
            'kaurna.utils.load_all_entries',
            Mock(
                return_value = [
                    {'secret_name':'password','deprecated':True,'secret_version':1},
                    {'secret_name':'password','deprecated':True,'secret_version':2},
                    {'secret_name':'password','deprecated':True,'secret_version':3}
                    ]
                )
            ).start()

        # WHEN
        get_secret(secret_name=secret_name, secret_version=secret_version)

        # THEN
        # Exception should get thrown and we should never get here

    def test_GIVEN_active_version_available_WHEN_get_secret_called_THEN_proper_secret_returned(self):
        self.fail()

    def test_GIVEN_iv_provided_WHEN_encrypt_with_key_called_THEN_plaintext_properly_encrypted(self):
        self.fail()

    def test_GIVEN_iv_not_provided_WHEN_encrypt_with_key_called_THEN_plaintext_properly_encrypted(self):
        self.fail()

    def test_WHEN_decrypt_with_key_called_THEN_plaintext_properly_decrypted(self):
        self.fail()

    def test_WHEN_encrypt_with_kms_called_THEN_proper_kms_call_made(self):
        self.fail()

    def test_WHEN_decrypt_with_kms_called_THEN_proper_kms_call_made(self):
        self.fail()
