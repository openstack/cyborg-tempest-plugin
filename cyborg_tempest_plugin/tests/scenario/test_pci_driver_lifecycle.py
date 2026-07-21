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

from tempest.common import compute
from tempest.common import utils
from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from cyborg_tempest_plugin.tests.scenario import manager

CONF = config.CONF


class TestPCIDriverLifecycle(manager.ScenarioTest):
    """Validate Nova/Cyborg lifecycle for generic PCI driver devices."""

    @classmethod
    def skip_checks(cls):
        super(TestPCIDriverLifecycle, cls).skip_checks()
        missing = []
        for opt in ('device_profile_name', 'vendor_id',
                    'product_id'):
            if not getattr(CONF.cyborg_pci, opt):
                missing.append('cyborg_pci.%s' % opt)
        if missing:
            raise cls.skipException(
                'Cyborg PCI lifecycle test requires %s' % ', '.join(missing))

    @staticmethod
    def _normalize_pci_id(pci_id):
        return pci_id.lower().removeprefix('0x')

    def _list_instance_arqs(self, server_id, bind_state=None):
        params = {'instance': server_id}
        if bind_state:
            params['bind_state'] = bind_state
        return self.os_admin.cyborg_client.list_accelerator_request(
            params=params)['arqs']

    def _get_bound_pci_arq(self, server_id):
        arqs = self._list_instance_arqs(server_id, bind_state='resolved')
        for arq in arqs:
            if arq.get('attach_handle_type') == 'PCI':
                return arq

    def _wait_for_bound_pci_arq(self, server_id):
        arq_holder = {}

        def wait_for_arq():
            arq = self._get_bound_pci_arq(server_id)
            if arq:
                arq_holder['arq'] = arq
                return True
            return False

        if not test_utils.call_until_true(
                wait_for_arq,
                CONF.compute.build_timeout,
                CONF.compute.build_interval):
            raise lib_exc.TimeoutException(
                'Timed out waiting for bound PCI ARQ for server %s' %
                server_id)
        return arq_holder['arq']

    def _assert_pci_arq(self, arq, server_id):
        self.assertEqual(server_id, arq['instance_uuid'])
        self.assertEqual('PCI', arq['attach_handle_type'])
        attach_info = arq['attach_handle_info']
        for field in ('domain', 'bus', 'device', 'function'):
            self.assertIn(field, attach_info)

        if 'managed' in attach_info:
            self.assertIn(attach_info['managed'], ('true', 'false'))

    def _assert_guest_has_pci_device(self, ssh_client):
        vendor_id = self._normalize_pci_id(CONF.cyborg_pci.vendor_id)
        product_id = self._normalize_pci_id(CONF.cyborg_pci.product_id)
        expected = '%s:%s' % (vendor_id, product_id)
        cmd = """
if command -v lspci >/dev/null 2>&1; then
    lspci -n
else
    for dev in /sys/bus/pci/devices/*; do
        if [ -r "$dev/vendor" ] && [ -r "$dev/device" ]; then
            printf '%s %s:%s\n' \
                "$(basename "$dev")" \
                "$(cat "$dev/vendor")" \
                "$(cat "$dev/device")"
        fi
    done
fi
"""
        output = ssh_client.exec_command(cmd)
        normalized = output.lower().replace('0x', '')
        self.assertIn(
            expected, normalized,
            'Expected PCI device %s in guest PCI devices:\n%s' %
            (expected, output))

    def _assert_instance_arqs_deleted(self, server_id):
        def wait_for_arqs_deleted():
            return not self._list_instance_arqs(server_id)

        if not test_utils.call_until_true(
                wait_for_arqs_deleted,
                CONF.compute.build_timeout,
                CONF.compute.build_interval):
            remaining = self._list_instance_arqs(server_id)
            self.fail('ARQs for server %s were not deleted: %s' %
                      (server_id, remaining))

    def _create_pci_server(self):
        keypair = self.create_keypair()
        security_group = self.create_security_group()
        flavor = self.create_accel_flavor(
            CONF.cyborg_pci.device_profile_name)

        server = self.create_server(
            keypair=keypair,
            security_groups=[{'name': security_group['name']}],
            name='cyborg-pci-lifecycle-test',
            image_id=CONF.compute.image_ref,
            flavor=flavor,
            wait_until='SSHABLE')
        arq = self._wait_for_bound_pci_arq(server['id'])
        self._assert_pci_arq(arq, server['id'])
        return server, keypair

    def _get_ssh_client(self, server, keypair):
        ssh_ip = self.get_server_ip(server)
        return self.get_remote_client(
            ssh_ip, private_key=keypair['private_key'], server=server)

    def _assert_server_pci_ready(self, server, keypair):
        arq = self._wait_for_bound_pci_arq(server['id'])
        self._assert_pci_arq(arq, server['id'])
        ssh_client = self._get_ssh_client(server, keypair)
        waiters.wait_for_ssh(ssh_client)
        self._assert_guest_has_pci_device(ssh_client)
        return ssh_client

    def _reboot_server(self, server, reboot_type):
        self.servers_client.reboot_server(server['id'], type=reboot_type)
        waiters.wait_for_server_status(
            self.servers_client, server['id'], 'ACTIVE')

    def _create_backup(self, server):
        name = data_utils.rand_name(
            prefix=CONF.resource_name_prefix, name='cyborg-pci-backup')
        resp = self.servers_client.create_backup(
            server['id'], backup_type='daily', rotation=1, name=name)
        image_id = resp.get('image_id')
        if not image_id:
            image_id = data_utils.parse_image_id(resp.response['location'])
        self.addCleanup(self.image_client.wait_for_resource_deletion,
                        image_id)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.image_client.delete_image, image_id)
        waiters.wait_for_image_status(self.image_client, image_id, 'active')

    @decorators.idempotent_id('1f6ef53b-9c65-4af9-b42f-c23389f7b529')
    @decorators.attr(type='smoke')
    @utils.services('compute', 'network')
    def test_create_delete_server_with_pci_driver_device(self):
        server, keypair = self._create_pci_server()
        self._assert_server_pci_ready(server, keypair)
        self.servers_client.delete_server(server['id'])
        waiters.wait_for_server_termination(
            self.servers_client, server['id'], ignore_error=False)
        self._assert_instance_arqs_deleted(server['id'])

    @decorators.idempotent_id('33412e4d-61b9-4cbd-80e0-e03c0dc296cc')
    @utils.services('compute', 'network')
    def test_guest_reboot_with_pci_driver_device(self):
        server, keypair = self._create_pci_server()
        ssh_client = self._assert_server_pci_ready(server, keypair)
        try:
            ssh_client.exec_command('sudo reboot')
        except lib_exc.SSHExecCommandFailed:
            pass
        try:
            waiters.wait_for_ssh(ssh_client)
        except lib_exc.TimeoutException:
            self.fail(
                f"Server {server['id']} did not start rebooting after guest "
                "reboot command"
                )
        self._assert_server_pci_ready(server, keypair)

    @decorators.idempotent_id('2da4cd2d-1a58-4347-8f51-98b65e3b853a')
    @utils.services('compute', 'network')
    def test_soft_reboot_server_with_pci_driver_device(self):
        server, keypair = self._create_pci_server()
        self._assert_server_pci_ready(server, keypair)
        self._reboot_server(server, 'SOFT')
        self._assert_server_pci_ready(server, keypair)

    @decorators.idempotent_id('2da914ba-7dd6-45fa-a604-e23e0bcecd59')
    @utils.services('compute', 'network')
    def test_hard_reboot_server_with_pci_driver_device(self):
        server, keypair = self._create_pci_server()
        self._assert_server_pci_ready(server, keypair)
        self._reboot_server(server, 'HARD')
        self._assert_server_pci_ready(server, keypair)

    @decorators.idempotent_id('b33d085c-8e97-41c1-8eef-6e31adbe06df')
    @utils.services('compute', 'network')
    def test_pause_unpause_server_with_pci_driver_device(self):
        server, keypair = self._create_pci_server()
        self.servers_client.pause_server(server['id'])
        waiters.wait_for_server_status(
            self.servers_client, server['id'], 'PAUSED')
        self.servers_client.unpause_server(server['id'])
        waiters.wait_for_server_status(
            self.servers_client, server['id'], 'ACTIVE')
        self._assert_server_pci_ready(server, keypair)

    @decorators.idempotent_id('0f74175e-6f02-4769-8f9e-339a57a136a4')
    @utils.services('compute', 'network', 'image')
    def test_snapshot_server_with_pci_driver_device(self):
        if not CONF.compute_feature_enabled.snapshot:
            raise self.skipException('Snapshotting is not available')
        server, keypair = self._create_pci_server()
        self.create_server_snapshot(server)
        self._assert_server_pci_ready(server, keypair)

    @decorators.idempotent_id('f6193834-bd47-4d81-8f5b-b84aabddd7e9')
    @utils.services('compute', 'network', 'image')
    def test_backup_server_with_pci_driver_device(self):
        if not CONF.compute_feature_enabled.snapshot:
            raise self.skipException('Snapshotting is not available')
        server, keypair = self._create_pci_server()
        self._create_backup(server)
        self._assert_server_pci_ready(server, keypair)

    @decorators.idempotent_id('efab040d-3003-4758-8ded-32a8e9f992bf')
    @utils.services('compute', 'network')
    def test_lock_unlock_server_with_pci_driver_device(self):
        server, keypair = self._create_pci_server()
        self.servers_client.lock_server(server['id'])
        self.servers_client.unlock_server(server['id'])
        waiters.wait_for_server_status(
            self.servers_client, server['id'], 'ACTIVE')
        self._assert_server_pci_ready(server, keypair)

    @decorators.idempotent_id('1b5baf1e-b97d-48cf-8ee7-b3e99b407b4c')
    @utils.services('compute', 'network')
    def test_rebuild_server_with_pci_driver_device(self):
        server, keypair = self._create_pci_server()
        self.rebuild_server(
            server['id'], image=CONF.compute.image_ref)
        self._assert_server_pci_ready(server, keypair)

    @decorators.idempotent_id('4d695479-afd5-45f2-a0bd-35a0fe20c1d2')
    @utils.services('compute', 'network', 'image')
    def test_shelve_unshelve_server_with_pci_driver_device(self):
        if not CONF.compute_feature_enabled.shelve:
            raise self.skipException('Shelve is not available')
        server, keypair = self._create_pci_server()
        compute.shelve_server(
            self.servers_client, server['id'], force_shelve_offload=True)
        body = self.servers_client.unshelve_server(server['id'])
        waiters.wait_for_server_status(
            self.servers_client, server['id'], 'ACTIVE',
            request_id=body.response['x-openstack-request-id'])
        self._assert_server_pci_ready(server, keypair)
