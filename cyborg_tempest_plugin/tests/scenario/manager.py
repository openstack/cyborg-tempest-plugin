# Copyright 2019 Intel, Corp.
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


from cyborg_tempest_plugin.services import cyborg_rest_client as clients
from cyborg_tempest_plugin.services.cyborg_rest_client import get_auth_provider

from oslo_log import log

from tempest.common import credentials_factory as common_creds
from tempest import config
from tempest.lib.common.utils import data_utils
import tempest.test


CONF = config.CONF

LOG = log.getLogger(__name__)


class ScenarioTest(tempest.scenario.manager.ScenarioTest):
    """Base class for scenario tests. Uses tempest own clients. """

    @classmethod
    def skip_checks(cls):
        super(ScenarioTest, cls).skip_checks()
        if not CONF.service_available.cyborg:
            raise cls.skipException('Cyborg support is required')

    @classmethod
    def setup_clients(cls):
        super(ScenarioTest, cls).setup_clients()

        cls.admin_flavors_client = cls.admin_manager.flavors_client

        credentials = common_creds.get_configured_admin_credentials(
            'identity_admin')
        auth_prov = get_auth_provider(credentials)
        cls.os_admin.cyborg_client = (
            clients.CyborgRestClient(auth_prov,
                                     'accelerator',
                                     CONF.identity.region))

    # ## Test functions library
    #
    # The create_[resource] functions only return body and discard the
    # resp part which is not used in scenario tests

    def update_flavor_extra_specs(self, specs, flavor):
        set_body = self.admin_flavors_client.set_flavor_extra_spec(
            flavor['id'], **specs)['extra_specs']
        self.assertEqual(set_body, specs)
        # GET extra specs and verify
        get_body = (self.admin_flavors_client.list_flavor_extra_specs(
            flavor['id'])['extra_specs'])
        self.assertEqual(get_body, specs)
        return flavor

    def create_flavor(self, client=None):
        if not client:
            client = self.admin_flavors_client
        flavor_id = CONF.compute.flavor_ref
        flavor_base = self.admin_flavors_client.show_flavor(
            flavor_id)['flavor']
        name = data_utils.rand_name(self.__class__.__name__)
        ram = flavor_base['ram']
        vcpus = flavor_base['vcpus']
        disk = flavor_base['disk']
        body = client.create_flavor(name=name, ram=ram, vcpus=vcpus, disk=disk)
        flavor = body["flavor"]
        self.addCleanup(client.delete_flavor, flavor["id"])
        return flavor["id"]

    def create_device_profile(self, data, client=None):
        if not client:
            client = self.os_admin.cyborg_client
        body = client.create_device_profile(data)
        device_profile = body["name"]
        self.addCleanup(client.delete_device_profile, device_profile)
        return body

    def create_accel_flavor(self, dp_name, client=None):
        if not client:
            client = self.admin_flavors_client
        flavor_id = CONF.compute.flavor_ref
        flavor_base = self.admin_flavors_client.show_flavor(
            flavor_id)['flavor']
        name = data_utils.rand_name(self.__class__.__name__)
        ram = flavor_base['ram']
        vcpus = flavor_base['vcpus']
        disk = flavor_base['disk']
        body = client.create_flavor(name=name, ram=ram, vcpus=vcpus, disk=disk)
        flavor = body["flavor"]
        specs = {"accel:device_profile": dp_name}
        self.update_flavor_extra_specs(specs, flavor)
        return flavor["id"]
