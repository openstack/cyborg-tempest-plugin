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


# Fake driver device profile used by all tests.
_FAKE_DP_GROUPS = [
    {"resources:FPGA": "1",
     "trait:CUSTOM_FPGA_1": "required",
     "trait:CUSTOM_FUNCTION_ID_3AFB": "required"}
]


class TestAcceleratorRequestController(base.BaseAPITest):

    @classmethod
    def skip_checks(cls):
        super(TestAcceleratorRequestController, cls).skip_checks()

    def _create_dp(self, name):
        """Create a device profile and register cleanup."""
        client = self.os_admin.cyborg_client
        dp = [{"name": name, "groups": _FAKE_DP_GROUPS}]
        client.create_device_profile(dp)
        self.addCleanup(client.delete_device_profile, name)
        return name

    def _create_arq(self, dp_name):
        """Create an ARQ and register cleanup."""
        client = self.os_admin.cyborg_client
        response = client.create_accelerator_request(
            {"device_profile_name": dp_name})
        arq_uuid = response['arqs'][0]['uuid']
        self.addCleanup(self._safe_delete_arq, arq_uuid)
        return arq_uuid, response

    def _safe_delete_arq(self, arq_uuid):
        """Delete an ARQ, ignoring errors (already deleted)."""
        try:
            self.os_admin.cyborg_client.delete_accelerator_request(arq_uuid)
        except Exception:
            pass

    @decorators.idempotent_id('b7d01588-7561-4774-bae3-2427d6d3a002')
    def test_create_accelerator_request(self):
        dp_name = self._create_dp("test_create_arq")
        response = self.os_admin.cyborg_client.create_accelerator_request(
            {"device_profile_name": dp_name})
        self.assertEqual(dp_name,
                         response['arqs'][0]['device_profile_name'])
        self.addCleanup(
            self.os_admin.cyborg_client.delete_accelerator_request,
            response['arqs'][0]['uuid'])

    @decorators.idempotent_id('be5dd697-fe6c-44f5-b6f2-bc92cebb7532')
    def test_list_get_delete_accelerator_request(self):
        dp_name = self._create_dp("test_list_get_delete_arq")
        arq_uuid, _ = self._create_arq(dp_name)

        # list
        response = self.os_admin.cyborg_client.list_accelerator_request()
        uuid_list = [it['uuid'] for it in response['arqs']]
        self.assertIn(arq_uuid, uuid_list)

        # get
        response = self.os_admin.cyborg_client.get_accelerator_request(
            arq_uuid)
        self.assertEqual(arq_uuid, response['uuid'])
        self.assertEqual(dp_name, response['device_profile_name'])

        # delete
        self.os_admin.cyborg_client.delete_accelerator_request(arq_uuid)
        response = self.os_admin.cyborg_client.list_accelerator_request()
        uuid_list = [it['uuid'] for it in response['arqs']]
        self.assertNotIn(arq_uuid, uuid_list)

    @classmethod
    def resource_cleanup(cls):
        super(TestAcceleratorRequestController, cls).resource_cleanup()
