#!/usr/bin/env python

from unittest import TestCase
from kaurna.utils import *

# http://www.openp2p.com/pub/a/python/2004/12/02/tdd_pyunit.html

class KaurnaUtilsTests(TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_GIVEN_kaurna_table_doesnt_exist_WHEN_get_kaurna_table_called_THEN_table_created_and_returned(self):
        self.fail()

    def test_GIVEN_kaurna_table_exists_WHEN_get_kaurna_table_called_THEN_table_returned(self):
        self.fail()

    def test_GIVEN_kaurna_key_doesnt_exist_WHEN_create_kaurna_key_called_THEN_kaurna_key_created(self):
        self.fail()

    def test_GIVEN_kaurna_key_exists_WHEN_create_kaurna_key_called_THEN_nothing_happens(self):
        self.fail()

    def test_WHEN_get_data_key_called_THEN_kaurna_key_created_and_data_key_generated(self):
        self.fail()

    # Don't really need to test; it's an entirely internal method with no network calls.
    # It's covered by other tests, but testing it separately makes it easy to pinpoint if it ever gets broken.
    def test_WHEN__generate_encryption_context_called_THEN_proper_encryption_context_generated(self):
        self.fail()

    def test_GIVEN_secret_not_provided_WHEN_store_secret_called_THEN_error_thrown(self):
        self.fail()

    def test_GIVEN_secret_name_not_provided_WHEN_store_secret_called_THEN_error_thrown(self):
        self.fail()

    def test_GIVEN_secret_version_exists_WHEN_store_secret_called_THEN_error_thrown(self):
        self.fail()

    def test_GIVEN_secret_version_not_provided_WHEN_store_secret_called_THEN_secret_properly_stored(self):
        self.fail()

    def test_GIVEN_secret_version_provided_WHEN_store_secret_called_THEN_secret_properly_stored(self):
        self.fail()

    def test_GIVEN_secret_version_but_not_secret_name_provided_WHEN_load_all_entries_called_THEN_error_thrown(self):
        self.fail()

    def test_GIVEN_secret_version_provided_WHEN_load_all_entries_called_THEN_proper_entries_returned(self):
        self.fail()

    def test_GIVEN_secret_name_but_not_secret_version_provided_WHEN_load_all_entries_called_THEN_proper_entries_returned(self):
        self.fail()

    def test_GIVEN_no_secret_information_provided_WHEN_load_all_entries_called_THEN_proper_entries_returned(self):
        self.fail()
    
    def test_WHEN_rotate_data_keys_called_THEN_data_keys_rotated(self):
        self.fail()

    def test_WHEN__reencrypt_item_and_save_called_THEN_item_reencrypted_and_saved(self):
        self.fail()

    def test_WHEN_update_secrets_called_THEN_proper_secrets_updated(self):
        self.fail()

    def test_GIVEN_provided_secret_name_is_None_WHEN_erase_secret_called_THEN_error_thrown(self):
        self.fail()

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

    def test_GIVEN_provided_secret_name_is_None_WHEN_get_secret_called_THEN_error_thrown(self):
        self.fail()

    def test_GIVEN_secret_not_found_WHEN_get_secret_called_THEN_error_thrown(self):
        self.fail()

    def test_GIVEN_all_secret_versions_are_deprecated_WHEN_get_secret_called_THEN_error_thrown(self):
        self.fail()

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
