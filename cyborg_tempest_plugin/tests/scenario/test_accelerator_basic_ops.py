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

from tempest import config
from tempest.common import utils
from tempest.common import waiters
from tempest.lib import decorators

from cyborg_tempest_plugin.services import cyborg_data
from cyborg_tempest_plugin.tests.scenario import manager


CONF = config.CONF


class TestServerBasicOps(manager.ScenarioTest):
    """The test suite for accelerator basic operations

    test_server_basic_ops follows this basic set of operations:
     * Create a keypair for use in launching an instance
     * Create a security group to control network access in instance
     * Add simple permissive rules to the security group
     * Launch an instance
     * Terminate the instance

    """

    @classmethod
    def skip_checks(cls):
        super().skip_checks()

    def setUp(self):
        super().setUp()

    @decorators.idempotent_id('7fff3fb3-91d8-4fd0-bd7d-0204f1f180ba')
    @decorators.attr(type='smoke')
    @utils.services('compute', 'network')
    def test_server_basic_ops(self):
        """Test for booting a VM with attached accelerator"""
        keypair = self.create_keypair()
        security_group = self.create_security_group()
        # flavor = self.create_flavor()
        response = self.create_device_profile(
            cyborg_data.SCENARIO_DEVICE_PROFILE_DATA
        )
        device_profile_name = response["name"]
        accl_flavor = self.create_accel_flavor(device_profile_name)
        self.instance = self.create_server(
            key_name=keypair['name'],
            security_groups=[{'name': security_group['name']}],
            name="cyborg-tempest-test-server",
            flavor=accl_flavor,
        )
        self.servers_client.delete_server(self.instance['id'])
        waiters.wait_for_server_termination(
            self.servers_client, self.instance['id'], ignore_error=False
        )


class TestFPGAProgram(manager.ScenarioTest):
    """Test FPGA programming via the Cyborg deployable API.

    Use the configured FPGA device profile, or create a fake driver profile
    when no profile is configured.

    """

    @classmethod
    def skip_checks(cls):
        super().skip_checks()
        if not CONF.cyborg.fpga_program:
            raise cls.skipException("FPGA programming tests are disabled.")

    @decorators.idempotent_id('c3d4e5f6-7890-1234-cdef-123456789012')
    @decorators.attr(type='smoke')
    @utils.services('compute', 'image', 'network')
    def test_fpga_program(self):
        """Program the FPGA deployable assigned to a server."""
        device_profile_name = CONF.cyborg_fpga.device_profile_name
        if not device_profile_name:
            response = self.create_device_profile(
                cyborg_data.FPGA_PROGRAM_DEVICE_PROFILE_DATA
            )
            device_profile_name = response['name']
        accel_flavor = self.create_accel_flavor(device_profile_name)

        server = self.create_server(
            name="cyborg-fpga-program-test", flavor=accel_flavor
        )

        client = self.os_admin.cyborg_client
        arqs = client.list_accelerator_request(
            params={'instance': server['id'], 'bind_state': 'resolved'}
        )['arqs']
        self.assertTrue(
            arqs, 'No bound ARQs found for server %s' % server['id']
        )
        device_rp_uuids = {arq['device_rp_uuid'] for arq in arqs}
        deployables = [
            deployable
            for deployable in client.list_deployables()['deployables']
            if deployable['rp_uuid'] in device_rp_uuids
        ]
        self.assertTrue(
            deployables, 'No deployable found for server %s' % server['id']
        )

        # image_create() uploads from CONF.scenario.img_file and registers
        # cleanup automatically.
        program_response = client.program_deployable(
            deployables[0]['uuid'], self.image_create(name='bitstream')
        )

        self.assertEqual(deployables[0]['uuid'], program_response['uuid'])
