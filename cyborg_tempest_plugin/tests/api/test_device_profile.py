# Copyright 2019 Intel, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from tempest.lib import decorators

from cyborg_tempest_plugin.services import cyborg_data
from cyborg_tempest_plugin.tests.api import base


class TestDeviceProfileController(base.BaseAPITest):

    @classmethod
    def skip_checks(cls):
        super(TestDeviceProfileController, cls).skip_checks()

    def _safe_delete_dp(self, name):
        """Delete a device profile by name, ignoring errors."""
        try:
            self.cyborg_admin_client.delete_device_profile(name)
        except Exception:
            pass

    @decorators.idempotent_id('59bee5a9-1af3-42bd-8a51-d7b5ecb2049f')
    def test_create_device_profile(self):
        dp = cyborg_data.make_device_profile_data(
            'dp-test-create')
        response = self.cyborg_admin_client.create_device_profile(
            dp)
        self.addCleanup(
            self._safe_delete_dp, dp[0]['name'])
        self.assertEqual(dp[0]['name'], response['name'])

    @decorators.idempotent_id('7e6276bc-49da-4915-a4ce-7ada60828096')
    def test_delete_multiple_device_profile(self):
        dp_one = cyborg_data.make_device_profile_data(
            'dp-batch-del-1')
        dp_two = cyborg_data.make_device_profile_data(
            'dp-batch-del-2')
        self.addCleanup(
            self._safe_delete_dp, dp_one[0]['name'])
        self.addCleanup(
            self._safe_delete_dp, dp_two[0]['name'])
        dp_one_resp = (
            self.cyborg_admin_client.create_device_profile(
                dp_one))
        dp_two_resp = (
            self.cyborg_admin_client.create_device_profile(
                dp_two))
        self.assertEqual(dp_one[0]['name'], dp_one_resp['name'])
        self.assertEqual(dp_two[0]['name'], dp_two_resp['name'])
        self.cyborg_admin_client \
            .delete_multiple_device_profile_by_names(
                dp_one[0]['name'], dp_two[0]['name'])
        list_resp = (
            self.cyborg_reader_client.list_device_profile())
        device_profile_list = list_resp['device_profiles']
        device_profile_name_list = [
            it['name'] for it in device_profile_list]
        self.assertNotIn(
            dp_one[0]['name'], device_profile_name_list)
        self.assertNotIn(
            dp_two[0]['name'], device_profile_name_list)

    @decorators.idempotent_id('10cc0ffe-a7a8-4c16-884f-fb3a10640fc1')
    def test_get_and_delete_device_profile(self):
        dp = cyborg_data.make_device_profile_data(
            'dp-test-get-del',
            description='dp-test-get-del-desc')
        self.addCleanup(
            self._safe_delete_dp, dp[0]['name'])
        create_resp = (
            self.cyborg_admin_client.create_device_profile(dp))
        device_profile_uuid = create_resp['uuid']
        self.assertEqual(dp[0]['name'], create_resp['name'])
        self.assertEqual(dp[0]['groups'], create_resp['groups'])
        self.assertEqual(
            dp[0]['description'], create_resp['description'])

        list_resp = (
            self.cyborg_reader_client.list_device_profile())
        device_profile_list = list_resp['device_profiles']
        device_profile_uuid_list = [
            it['uuid'] for it in device_profile_list]
        self.assertIn(
            device_profile_uuid, device_profile_uuid_list)

        get_resp = self.cyborg_reader_client.get_device_profile(
            device_profile_uuid)
        self.assertEqual(
            dp[0]['name'],
            get_resp['device_profile']['name'])
        self.assertEqual(
            device_profile_uuid,
            get_resp['device_profile']['uuid'])

        self.cyborg_admin_client.delete_device_profile_by_uuid(
            device_profile_uuid)
        list_resp = (
            self.cyborg_reader_client.list_device_profile())
        device_profile_list = list_resp['device_profiles']
        device_profile_uuid_list = [
            it['uuid'] for it in device_profile_list]
        self.assertNotIn(
            device_profile_uuid, device_profile_uuid_list)

    @decorators.idempotent_id('292998b7-418b-491b-8876-0fb71a447b49')
    def test_delete_device_profile_by_name(self):
        dp = cyborg_data.make_device_profile_data(
            'dp-test-del-name')
        self.addCleanup(
            self._safe_delete_dp, dp[0]['name'])
        response = self.cyborg_admin_client.create_device_profile(
            dp)
        self.assertEqual(dp[0]['name'], response['name'])
        self.cyborg_admin_client.delete_device_profile(
            dp[0]['name'])
        list_resp = (
            self.cyborg_reader_client.list_device_profile())
        device_profile_list = list_resp['device_profiles']
        device_profile_name_list = [
            it['name'] for it in device_profile_list]
        self.assertNotIn(
            dp[0]['name'], device_profile_name_list)

    @classmethod
    def resource_cleanup(cls):
        super(TestDeviceProfileController, cls).resource_cleanup()
