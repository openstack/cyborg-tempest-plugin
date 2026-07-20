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

import socket

from oslo_log import log as logging
from tempest.common import compute
from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

CONF = config.CONF
LOG = logging.getLogger(__name__)


class DriverLifecycleMixin:
    """Mixin providing shared helpers for driver lifecycle scenario tests.

    Subclasses must set the class attribute ``attach_handle_type``
    and override ``_assert_device_arq``.
    """

    attach_handle_type = None

    @property
    def _lifecycle_params(self):
        return dict(
            image_ref=CONF.cyborg.image_ref or CONF.compute.image_ref,
            flavor_ref=CONF.cyborg.flavor_ref or CONF.compute.flavor_ref,
        )

    @staticmethod
    def _normalize_pci_id(pci_id):
        return pci_id.lower().removeprefix('0x')

    def _list_instance_arqs(self, server_id, bind_state=None):
        params = {'instance': server_id}
        if bind_state:
            params['bind_state'] = bind_state
        return self.os_admin.cyborg_client.list_accelerator_request(
            params=params
        )['arqs']

    def _get_bound_arq(self, server_id):
        arqs = self._list_instance_arqs(server_id, bind_state='resolved')
        for arq in arqs:
            if arq.get('attach_handle_type') == self.attach_handle_type:
                return arq

    def _wait_for_bound_arq(self, server_id):
        arq_holder = {}

        def wait_for_arq():
            arq = self._get_bound_arq(server_id)
            if arq:
                arq_holder['arq'] = arq
                return True
            return False

        if not test_utils.call_until_true(
            wait_for_arq,
            CONF.compute.build_timeout,
            CONF.compute.build_interval,
        ):
            raise lib_exc.TimeoutException(
                f"Timed out waiting for bound {self.attach_handle_type} ARQ "
                f"for server {server_id}"
            )
        return arq_holder['arq']

    def _assert_device_arq(self, arq, server_id):
        raise NotImplementedError

    def _assert_guest_has_device(self, ssh_client,
                                 vendor_id, product_id):
        vendor_id = self._normalize_pci_id(vendor_id)
        product_id = self._normalize_pci_id(product_id)
        expected = "%s:%s" % (vendor_id, product_id)
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
            expected,
            normalized,
            'Expected PCI device %s in guest PCI devices:\n%s'
            % (expected, output),
        )

    def _run_device_specific_validation(self, ssh_client):
        pass

    def _assert_instance_arqs_deleted(self, server_id):
        def wait_for_arqs_deleted():
            return not self._list_instance_arqs(server_id)

        if not test_utils.call_until_true(
            wait_for_arqs_deleted,
            CONF.compute.build_timeout,
            CONF.compute.build_interval,
        ):
            remaining = self._list_instance_arqs(server_id)
            self.fail(
                f"ARQs for server {server_id} were not deleted: {remaining}"
            )

    def _create_server_with_device(self, device_profile_name,
                                   image_ref, flavor_ref):
        keypair = self.create_keypair()
        security_group = self.create_security_group()
        flavor = self.create_accel_flavor(
            device_profile_name,
            flavor_ref=flavor_ref,
        )

        server = self.create_server(
            keypair=keypair,
            security_groups=[{'name': security_group['name']}],
            name=f"cyborg-{self.attach_handle_type.lower()}-lifecycle-test",
            image_id=image_ref,
            flavor=flavor,
            wait_until='SSHABLE',
        )
        arq = self._wait_for_bound_arq(server['id'])
        self._assert_device_arq(arq, server['id'])
        return server, keypair

    def _get_ssh_client(self, server, keypair):
        ssh_ip = self.get_server_ip(server)
        return self.get_remote_client(
            ssh_ip, private_key=keypair['private_key'], server=server
        )

    def _assert_server_device_ready(self, server, keypair,
                                    vendor_id, product_id):
        arq = self._wait_for_bound_arq(server['id'])
        self._assert_device_arq(arq, server['id'])
        ssh_client = self._get_ssh_client(server, keypair)
        waiters.wait_for_ssh(ssh_client)
        self._assert_guest_has_device(
            ssh_client, vendor_id, product_id)
        self._run_device_specific_validation(ssh_client)
        return ssh_client

    def _reboot_server(self, server, reboot_type):
        self.servers_client.reboot_server(server['id'], type=reboot_type)
        waiters.wait_for_server_status(
            self.servers_client, server['id'], 'ACTIVE'
        )

    def _create_backup(self, server):
        name = data_utils.rand_name(
            prefix=CONF.resource_name_prefix,
            name=f"cyborg-{self.attach_handle_type.lower()}-backup",
        )
        resp = self.servers_client.create_backup(
            server['id'], backup_type='daily', rotation=1, name=name
        )
        image_id = resp.get('image_id')
        if not image_id:
            image_id = data_utils.parse_image_id(resp.response['location'])
        self.addCleanup(self.image_client.wait_for_resource_deletion, image_id)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.image_client.delete_image,
            image_id,
        )
        waiters.wait_for_image_status(self.image_client, image_id, 'active')

    def _run_create_delete_server(self, device_profile_name,
                                  image_ref, flavor_ref,
                                  vendor_id, product_id):
        server, keypair = self._create_server_with_device(
            device_profile_name, image_ref, flavor_ref)
        self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)
        self.servers_client.delete_server(server['id'])
        waiters.wait_for_server_termination(
            self.servers_client, server['id'], ignore_error=False
        )
        self._assert_instance_arqs_deleted(server['id'])

    def _run_guest_reboot(self, device_profile_name,
                          image_ref, flavor_ref,
                          vendor_id, product_id):
        server, keypair = self._create_server_with_device(
            device_profile_name, image_ref, flavor_ref)
        ssh_client = self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)
        try:
            ssh_client.exec_command('sudo reboot')
        except lib_exc.SSHExecCommandFailed:
            pass
        self._wait_for_guest_unreachable(self.get_server_ip(server))
        try:
            waiters.wait_for_ssh(ssh_client)
        except lib_exc.TimeoutException:
            self.fail(
                f"Server {server['id']} did not start rebooting after guest "
                "reboot command"
                )
        self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)

    def _run_soft_reboot(self, device_profile_name,
                         image_ref, flavor_ref,
                         vendor_id, product_id):
        server, keypair = self._create_server_with_device(
            device_profile_name, image_ref, flavor_ref)
        self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)
        self._reboot_server(server, 'SOFT')
        self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)

    def _run_hard_reboot(self, device_profile_name,
                         image_ref, flavor_ref,
                         vendor_id, product_id):
        server, keypair = self._create_server_with_device(
            device_profile_name, image_ref, flavor_ref)
        self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)
        self._reboot_server(server, 'HARD')
        self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)

    def _run_pause_unpause(self, device_profile_name,
                           image_ref, flavor_ref,
                           vendor_id, product_id):
        server, keypair = self._create_server_with_device(
            device_profile_name, image_ref, flavor_ref)
        self.servers_client.pause_server(server['id'])
        waiters.wait_for_server_status(
            self.servers_client, server['id'], 'PAUSED'
        )
        self.servers_client.unpause_server(server['id'])
        waiters.wait_for_server_status(
            self.servers_client, server['id'], 'ACTIVE'
        )
        self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)

    def _run_snapshot(self, device_profile_name,
                      image_ref, flavor_ref,
                      vendor_id, product_id):
        if not CONF.compute_feature_enabled.snapshot:
            raise self.skipException('Snapshotting is not available')
        server, keypair = self._create_server_with_device(
            device_profile_name, image_ref, flavor_ref)
        self.create_server_snapshot(server)
        self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)

    def _run_backup(self, device_profile_name,
                    image_ref, flavor_ref,
                    vendor_id, product_id):
        if not CONF.compute_feature_enabled.snapshot:
            raise self.skipException('Snapshotting is not available')
        server, keypair = self._create_server_with_device(
            device_profile_name, image_ref, flavor_ref)
        self._create_backup(server)
        self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)

    def _run_lock_unlock(self, device_profile_name,
                         image_ref, flavor_ref,
                         vendor_id, product_id):
        server, keypair = self._create_server_with_device(
            device_profile_name, image_ref, flavor_ref)
        self.servers_client.lock_server(server['id'])
        self.servers_client.unlock_server(server['id'])
        waiters.wait_for_server_status(
            self.servers_client, server['id'], 'ACTIVE'
        )
        self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)

    def _run_rebuild(self, device_profile_name,
                     image_ref, flavor_ref,
                     vendor_id, product_id):
        server, keypair = self._create_server_with_device(
            device_profile_name, image_ref, flavor_ref)
        self.rebuild_server(server['id'], image=image_ref)
        self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)

    def _run_shelve_unshelve(self, device_profile_name,
                             image_ref, flavor_ref,
                             vendor_id, product_id):
        if not CONF.compute_feature_enabled.shelve:
            raise self.skipException('Shelve is not available')
        server, keypair = self._create_server_with_device(
            device_profile_name, image_ref, flavor_ref)
        compute.shelve_server(
            self.servers_client, server['id'], force_shelve_offload=True
        )
        body = self.servers_client.unshelve_server(server['id'])
        waiters.wait_for_server_status(
            self.servers_client,
            server['id'],
            'ACTIVE',
            request_id=body.response['x-openstack-request-id'],
        )
        self._assert_server_device_ready(
            server, keypair, vendor_id, product_id)

    def _wait_for_guest_unreachable(self, ip, port=22):
        """Ensure guest is not reachable after a reboot."""
        def _check():
            try:
                with socket.create_connection((ip, port), timeout=5):
                    LOG.debug(f"Connection to {ip}: {port} successful")
            except OSError:
                LOG.debug(f"Connection to {ip}: {port} failed")
                return True
            return False

        if not test_utils.call_until_true(
                _check,
                CONF.compute.build_timeout,
                CONF.compute.build_interval):
            raise lib_exc.TimeoutException(
                'SSH port still reachable after reboot command'
            )
