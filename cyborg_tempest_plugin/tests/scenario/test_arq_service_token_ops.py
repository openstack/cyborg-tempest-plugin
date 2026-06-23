# Copyright 2026 Red Hat, Inc.
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

from tempest.common import utils
from tempest.common import waiters
from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from cyborg_tempest_plugin.services import cyborg_data
from cyborg_tempest_plugin.services import cyborg_rest_client as clients
from cyborg_tempest_plugin.tests.scenario import manager

CONF = config.CONF


class TestARQServiceTokenOps(manager.ScenarioTest):
    """Test ARQ operations that require a service token (LP#2144056).

    Bound ARQs (those attached to a Nova instance) can only be deleted
    via delete-by-instance-uuid with a valid service token.  This test
    boots a real VM with an accelerator, verifies the bound ARQ exists,
    and then exercises the delete-by-instance path.
    """

    credentials = ['primary', 'admin', ['service_user', 'service']]

    @classmethod
    def skip_checks(cls):
        super(TestARQServiceTokenOps, cls).skip_checks()

    @classmethod
    def setup_clients(cls):
        super(TestARQServiceTokenOps, cls).setup_clients()
        cls._service_token = (
            cls.os_service_user.auth_provider.get_token())

    @decorators.idempotent_id('a4c1e7b2-3d5f-4a8e-9b0c-1d2e3f4a5b6c')
    @decorators.attr(type='smoke')
    @utils.services('compute', 'network')
    def test_delete_bound_arq_by_instance_uuid(self):
        """Delete bound ARQs by instance UUID requires a service token."""
        keypair = self.create_keypair()
        security_group = self.create_security_group()

        response = self.create_device_profile(
            cyborg_data.SERVICE_TOKEN_DEVICE_PROFILE_DATA)
        device_profile_name = response["name"]
        accl_flavor = self.create_accel_flavor(device_profile_name)

        server = self.create_server(
            key_name=keypair['name'],
            security_groups=[{'name': security_group['name']}],
            name="cyborg-svc-token-test",
            flavor=accl_flavor)
        instance_uuid = server['id']

        # Verify a bound ARQ exists for this instance.
        client = self.os_admin.cyborg_client
        arqs = client.list_accelerator_request()['arqs']
        bound = [a for a in arqs if a['instance_uuid'] == instance_uuid]
        self.assertTrue(
            len(bound) > 0,
            "Expected at least one bound ARQ for instance %s" % instance_uuid)

        # Deleting bound ARQs without a service token must fail.
        exc = self.assertRaises(
            lib_exc.Forbidden,
            client.delete_accelerator_request_by_instance_uuid,
            instance_uuid)
        self.assertIn(
            'requires a service token',
            str(exc).lower())

        # Stop the server first so Nova releases its side, allowing
        # Cyborg to cleanly delete the ARQs. create_server() already
        # registered server deletion cleanup, so teardown still removes
        # the server if the service-token delete below fails.
        self.servers_client.stop_server(instance_uuid)
        waiters.wait_for_server_status(
            self.servers_client, instance_uuid, 'SHUTOFF')

        # Delete with a service token succeeds. A dedicated client
        # instance carries the service token so the shared admin
        # client is not mutated. The auth provider is intentionally
        # reused so this client has the same admin identity and only
        # differs by the injected X-Service-Token header.
        svc_client = clients.CyborgRestClient(
            self.os_admin.cyborg_client.auth_provider,
            'accelerator',
            CONF.identity.region,
            service_token=self._service_token)
        svc_client.delete_accelerator_request_by_instance_uuid(
            instance_uuid)

        # Verify the ARQs are gone.
        arqs = client.list_accelerator_request()['arqs']
        remaining = [a for a in arqs if a['instance_uuid'] == instance_uuid]
        self.assertEqual(
            [], remaining,
            "ARQs for instance %s should have been deleted" % instance_uuid)
        # Server cleanup is handled by create_server's addCleanup.
