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

from cyborg_tempest_plugin.tests.api import base


class TestAcceleratorRequestController(base.BaseAPITest):

    credentials = ['admin']

    def test_create_accelerator_request(self):
        dp = [{
            "name": "test_example_1",
            "groups": [
                {"resources:FPGA": "1",
                 "trait:CUSTOM_FPGA_1": "required",
                 "trait:CUSTOM_FUNCTION_ID_3AFB": "required",
                 }
                ]
        }]
        response = self.os_admin.cyborg_client.create_device_profile(dp)
        device_profile_name = response['name']
        self.addCleanup(self.os_admin.cyborg_client.delete_device_profile,
                        dp[0]['name'])
        response = self.os_admin.cyborg_client.create_accelerator_request(
            {"device_profile_name": device_profile_name})
        self.assertEqual(device_profile_name,
                         response['arqs'][0]['device_profile_name'])
        self.addCleanup(self.os_admin.cyborg_client.delete_accelerator_request,
                        response['arqs'][0]['uuid'])

    @classmethod
    def resource_cleanup(cls):
        super(TestAcceleratorRequestController, cls).resource_cleanup()
