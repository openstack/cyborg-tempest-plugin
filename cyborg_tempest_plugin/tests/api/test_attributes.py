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


class TestAttributes(base.BaseAPITest):

    @decorators.idempotent_id('1bf7d6a8-24bd-4906-b3a3-1a212b7b6d5c')
    def test_list_attributes(self):
        response = self.cyborg_manager_client.list_attributes()
        self.assertIn('attributes', response)

    @decorators.idempotent_id('79a762ef-b448-4b62-a44e-b633ada87de9')
    def test_get_attribute(self):
        response = self.cyborg_manager_client.list_attributes()
        attributes = response['attributes']
        if not attributes:
            self.skipTest('No attributes available')
        attr_id = attributes[0]['uuid']
        response = self.cyborg_manager_client.get_attributes(attr_id)
        self.assertEqual(attr_id, response['uuid'])
