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
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc
import tempest.test


CONF = config.CONF

LOG = log.getLogger(__name__)


class ScenarioTest(tempest.scenario.manager.ScenarioTest):
    """Base class for scenario tests. Uses tempest own clients. """

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(ScenarioTest, cls).skip_checks()
        if not CONF.service_available.cyborg:
            raise cls.skipException('Cyborg support is required')

    @classmethod
    def setup_clients(cls):
        super(ScenarioTest, cls).setup_clients()
        # Clients
        cls.admin_flavors_client = cls.admin_manager.flavors_client
        if CONF.service_available.glance:
            # Check if glance v1 is available to determine which client to use.
            if CONF.image_feature_enabled.api_v1:
                cls.image_client = cls.os_primary.image_client
            elif CONF.image_feature_enabled.api_v2:
                cls.image_client = cls.os_primary.image_client_v2
            else:
                raise lib_exc.InvalidConfiguration(
                    'Either api_v1 or api_v2 must be True in '
                    '[image-feature-enabled].')
        # Compute image client
        cls.compute_images_client = cls.os_primary.compute_images_client
        cls.keypairs_client = cls.os_primary.keypairs_client
        # Nova security groups client
        cls.compute_security_groups_client = (
            cls.os_primary.compute_security_groups_client)
        cls.compute_security_group_rules_client = (
            cls.os_primary.compute_security_group_rules_client)
        cls.servers_client = cls.os_primary.servers_client
        # Neutron network client
        cls.networks_client = cls.os_primary.networks_client
        cls.ports_client = cls.os_primary.ports_client

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

    def _create_loginable_secgroup_rule(self, secgroup_id=None):
        _client = self.compute_security_groups_client
        _client_rules = self.compute_security_group_rules_client
        if secgroup_id is None:
            sgs = _client.list_security_groups()['security_groups']
            for sg in sgs:
                if sg['name'] == 'default':
                    secgroup_id = sg['id']

        # These rules are intended to permit inbound ssh and icmp
        # traffic from all sources, so no group_id is provided.
        # Setting a group_id would only permit traffic from ports
        # belonging to the same security group.
        rulesets = [
            {
                # ssh
                'ip_protocol': 'tcp',
                'from_port': 22,
                'to_port': 22,
                'cidr': '0.0.0.0/0',
            },
            {
                # ping
                'ip_protocol': 'icmp',
                'from_port': -1,
                'to_port': -1,
                'cidr': '0.0.0.0/0',
            }
        ]
        rules = list()
        for ruleset in rulesets:
            sg_rule = _client_rules.create_security_group_rule(
                parent_group_id=secgroup_id, **ruleset)['security_group_rule']
            rules.append(sg_rule)
        return rules

    def _create_security_group(self):
        # Create security group
        sg_name = data_utils.rand_name(self.__class__.__name__)
        sg_desc = sg_name + " description"
        secgroup = self.compute_security_groups_client.create_security_group(
            name=sg_name, description=sg_desc)['security_group']
        self.assertEqual(secgroup['name'], sg_name)
        self.assertEqual(secgroup['description'], sg_desc)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.compute_security_groups_client.delete_security_group,
            secgroup['id'])

        # Add rules to the security group
        self._create_loginable_secgroup_rule(secgroup['id'])

        return secgroup
