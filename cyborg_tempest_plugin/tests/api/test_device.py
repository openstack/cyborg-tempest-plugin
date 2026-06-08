# Copyright 2020 Inspur, Inc.
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

from cyborg_tempest_plugin.tests.api import base


class TestDevice(base.BaseAPITest):

    @classmethod
    def skip_checks(cls):
        super(TestDevice, cls).skip_checks()

    @decorators.idempotent_id('6f4bf672-1b8e-4e3e-8562-de64093bad52')
    def test_list_get_device(self):
        response = self.cyborg_manager_client.list_devices()
        self.assertEqual('devices', list(response.keys())[0])

        device_uuid = response['devices'][0]['uuid']
        response = self.cyborg_manager_client.get_device(device_uuid)
        self.assertEqual(device_uuid, response['uuid'])

    @decorators.idempotent_id('61096874-0b10-4b12-954f-f03eb0e59f5d')
    def test_list_devices_filter_by_type(self):
        response = self.cyborg_manager_client.list_devices()
        type_name = response['devices'][0]['type']

        # list devices filter by type
        params = {"type": type_name}
        response = self.cyborg_manager_client.list_devices(params=params)
        self.assertNotEmpty(response['devices'])
        for dv in response['devices']:
            self.assertEqual(type_name, dv['type'])

    @decorators.idempotent_id('f55cc5a7-bfc0-49a2-bcc9-d4b512efd2c6')
    def test_list_devices_filter_by_non_exist_type(self):
        # list devices filter by non exist type
        params = {"type": "fake_type"}
        response = self.cyborg_manager_client.list_devices(params=params)
        self.assertEmpty(response['devices'])

    @decorators.idempotent_id('f501b343-a7e4-41a7-8e02-ab6725714bbf')
    def test_list_devices_filter_by_vendor(self):
        response = self.cyborg_manager_client.list_devices()
        vendor = response['devices'][0]['vendor']

        # list devices filter by vendor
        params = {"vendor": vendor}
        response = self.cyborg_manager_client.list_devices(params=params)
        self.assertNotEmpty(response['devices'])
        for dv in response['devices']:
            self.assertEqual(vendor, dv['vendor'])

    @decorators.idempotent_id('8dba0f88-2db6-4001-9e99-fe668512eb09')
    def test_list_devices_filter_by_non_exist_vendor(self):
        # list devices filter by non exist vendor
        params = {"vendor": "fake_vendor"}
        response = self.cyborg_manager_client.list_devices(params=params)
        self.assertEmpty(response['devices'])

    @decorators.idempotent_id('ae34fb47-6079-4cc4-817d-5954a149d0d8')
    def test_list_devices_filter_by_hostname(self):
        response = self.cyborg_manager_client.list_devices()
        hostname = response['devices'][0]['hostname']

        # list devices filter by hostname
        params = {"hostname": hostname}
        response = self.cyborg_manager_client.list_devices(params=params)
        self.assertNotEmpty(response['devices'])
        for dv in response['devices']:
            self.assertEqual(hostname, dv['hostname'])

    @decorators.idempotent_id('98e54bb5-001d-428c-81e2-8443220bd720')
    def test_list_devices_filter_by_non_exist_hostname(self):
        # list devices filter by non exist hostname
        params = {"hostname": "fake_hostname"}
        response = self.cyborg_manager_client.list_devices(params=params)
        self.assertEmpty(response['devices'])

    @decorators.idempotent_id('0ee1ff4c-b667-4706-8372-5db3d205af8d')
    def test_list_devices_filter_by_combine_args(self):
        # list devices filter by combine args
        response = self.cyborg_manager_client.list_devices()
        type_name = response['devices'][0]['type']
        vendor = response['devices'][0]['vendor']
        hostname = response['devices'][0]['hostname']
        params = {
            "type": type_name,
            "hostname": hostname,
            "vendor": vendor
        }
        response = self.cyborg_manager_client.list_devices(params=params)
        self.assertNotEmpty(response['devices'])
        for dv in response['devices']:
            self.assertEqual(type_name, dv['type'])
            self.assertEqual(vendor, dv['vendor'])
            self.assertEqual(hostname, dv['hostname'])

    @classmethod
    def resource_cleanup(cls):
        super(TestDevice, cls).resource_cleanup()
