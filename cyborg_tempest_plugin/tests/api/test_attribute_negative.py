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

import uuid

from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from cyborg_tempest_plugin.tests.api import base


class AttributeNegativeTest(base.BaseAPITest):

    @decorators.attr(type=['negative', 'gate'])
    @decorators.idempotent_id('6e96d2b4-b948-46b3-9562-817fcbddfa7f')
    def test_get_non_existent_attribute(self):
        non_existent_id = str(uuid.uuid4())
        self.assertRaises(
            lib_exc.NotFound,
            self.cyborg_manager_client.get_attributes,
            non_existent_id)
