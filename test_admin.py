import unittest
import logging
import grpc
import admin
from session_manager_server import (sm_pb2_grpc,
                                    sm_pb2,
                                    generate_access_token)
from db.interface import Database
from db import ConsumerCredential, ConsumerDevice, Task, ProviderCredential, ProviderDevice
class TestInterface(unittest.TestCase):
    global log
    log = logging.getLogger("session_manager_admin")
    def setUp(self, db_file="sessions.db", db_create=True, logger=None):
        global db
        db = Database(db_file, db_create, logger)

    def add_credential(self, username, password):
        cred = db.add(ConsumerCredential, username = username, password = db.hash_password(password))
        if cred:
            log.info("credential with username '{}' added".format(username))
        else:
            log.error("error adding '{}'!".format(username))
        return cred

    def add_device(self, username, password, device_name):
        cred = db.query(ConsumerCredential,
                    username=username,
                    password=password)
        device = db.query(ConsumerDevice,
                        username=username,
                        device_name=device_name)
        if cred and not device:
            if db.add(ConsumerDevice,
                    username=username,
                    device_name=device_name):
                log.info("Device '{}' added to User '{}'.".format(device_name,
                                                                username))
        else:
            log.error("Error adding device '{}'!".format(device_name))

        return device
    
    def activate_device(self, username, password, device_name):
        cred = db.query(ConsumerCredential,
                    username=username,
                    password=password)
        device = db.query(ConsumerDevice,
                        username=username,
                        device_name=device_name)
        if cred and device:
            db.update(ConsumerCredential,
                    where={"username": username},
                    update={"active_device": device_name})
            log.info("Device '{}' is active".format(device_name))
        else:
            log.error("Error activating device '{}'!".format(device_name))

        return device

    def add_provider(self, providername, password):
        provider = db.add(ProviderCredential, providername=providername, password=db.hash_password(password))
        if provider:
            log.info("Provider Credential with username '{}' added.".format(providername))
        else:
            log.error("Error adding '{}'!".format(providername))
        return provider

    def add_provider_device(self, providername, password, device_name):
        pcred = db.query_all(ProviderCredential)
        pdevice = db.query(ProviderDevice,
                        providername=providername,
                        device_name=device_name)
        if pcred and not pdevice:
            if db.add(ProviderDevice,
                    providername=providername,
                    device_name=device_name):
                log.info("Device '{}' added to User '{}'.".format(device_name,
                                                                providername))
        else:
            log.error("Error adding device '{}'!".format(device_name))

        return pcred

    def delete_one_provider_credential(self, providername):
        delete_provider = db.delete(ProviderCredential, providername = providername)
        if delete_provider:
            log.info("Provider '{}' deleted.".format(providername))
        else:
            log.error("Error deleting user '{}'!".format(providername))

        return delete_provider
    def delete_all_provider_credentials(self):
        all_entries = db.query_all(ProviderCredential)
        for c in all_entries:
            db.delete(ProviderCredential, providername = c.providername)

    def delete_provider_device(self, providername, password, device_name):
        pcred = db.query(ProviderCredential,
                        providername=providername,
                        password= device_name)
        pdevice = db.query(ProviderDevice,
                            providername = providername,
                            device_name = device_name)
        
        if pcred and pdevice:
            if db.delete(ProviderDevice, dev_id=pdevice.dev_id):
                log.info("Provider Device '{}' deleted.".format(device_name))
                return
        log.error("Error deleting provider  device '{}'!".format(device_name))

    def delete_one_credential(self, username):
        if db.delete(ConsumerCredential, username=username):
            log.info("User '{}' deleted.".format(username))
        else:
            log.error("Error deleting user '{}'!".format(username))
    def delete_device(self, username, password, device_name):
        cred = db.query(ConsumerCredential,
                    username=username,
                    password=password)
        device = db.query(ConsumerDevice,
                        username=username,
                        device_name=device_name)
        if cred and device:
            if db.delete(ConsumerDevice, dev_id=device.dev_id):
                log.info("Device '{}' deleted.".format(device_name))
                return
        log.error("Error deleting device '{}'!".format(device_name))


    # unittest for diferenet testcase
    def test_add_credential(self):
        # testing for addCredential
        user_1 = self.add_credential("username_1", "1234")
        self.assertTrue(user_1, True)
        cred = db.query_all(ConsumerCredential)
        self.assertIsNot(cred, "is not none")

        #testing for addDevice
        device1 = self.add_device("username_1", "1234", "samusung")
        device1 = db.query_all(ConsumerDevice)
        self.assertIsNotNone(device1, "is not none")

        # testing for activateDevice
        active_deviice1 = self.activate_device("username_1", "1234", "samusung")
        active_deviice1 = db.query_all(ConsumerCredential)
        self.assertIsNotNone(active_deviice1, "is not none")

        # testing for addprovider
        provider1 = self.add_provider("provider_1", "1234")
        self.assertTrue(provider1, True)
        provider1 = db.query_all(ProviderCredential)
        self.assertIsNotNone(provider1, "is not None")

        # testing for add_provider_device
        provider_device = self.add_provider_device("provider_1", "1234", "nokia")
        provider_device = db.query_all(ProviderDevice)
        self.assertIsNotNone(provider_device, "is not None")

        #testing deleting one provider credential
        deleting_provider = self.delete_one_provider_credential("provider_1")
        self.assertTrue(deleting_provider, True)
        provider1 = db.query_all(ProviderCredential)
        self.assertEqual(provider1, [])

        # testing deleting all entries for provider
        deleting_all_entries_provider = self.delete_all_provider_credentials()
        self.assertEqual(deleting_all_entries_provider, None)

        # testing deleting provider device
        delete_provider_device = self.delete_provider_device("provider_1", "1234", "nokia")
        self.assertEqual(delete_provider_device, None)
        device1 = db.query_all(ProviderDevice)
        self.assertEqual(device1, [])

        # testing for deleting one usercredential
        delete_user = self.delete_one_credential("username_1")
        self.assertEqual(delete_user, None)
        cred = db.query_all(ConsumerCredential)
        self.assertEqual(cred, [])
        
        # testing for delete_device
        delete_device = self.delete_device("username_1", "1234", "samusung")
        self.assertEqual(delete_device, None)




if __name__ == "__main__":
    unittest.main()
        