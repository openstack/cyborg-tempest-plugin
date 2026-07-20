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
from tempest import config
from tempest.lib import decorators

from cyborg_tempest_plugin.tests.scenario import driver_lifecycle_base
from cyborg_tempest_plugin.tests.scenario import manager

CONF = config.CONF


class TestPCIDriverLifecycle(
    driver_lifecycle_base.DriverLifecycleMixin, manager.ScenarioTest
):
    """Validate Nova/Cyborg lifecycle for generic PCI driver devices."""

    attach_handle_type = 'PCI'

    @property
    def _lifecycle_params(self):
        params = super()._lifecycle_params
        params.update(
            device_profile_name=CONF.cyborg_pci.device_profile_name,
            vendor_id=CONF.cyborg_pci.vendor_id,
            product_id=CONF.cyborg_pci.product_id,
        )
        return params

    @classmethod
    def skip_checks(cls):
        super().skip_checks()
        missing = []

        if not CONF.cyborg_pci.device_profile_name:
            missing.append('cyborg_pci.device_profile_name')
        if not CONF.cyborg_pci.vendor_id:
            missing.append('cyborg_pci.vendor_id')
        if not CONF.cyborg_pci.product_id:
            missing.append('cyborg_pci.product_id')
        if missing:
            raise cls.skipException(
                f"Cyborg PCI lifecycle test requires {', '.join(missing)}"
            )

    def _assert_device_arq(self, arq, server_id):
        self.assertEqual(server_id, arq['instance_uuid'])
        self.assertEqual('PCI', arq['attach_handle_type'])
        attach_info = arq['attach_handle_info']
        for field in ('domain', 'bus', 'device', 'function'):
            self.assertIn(field, attach_info)

        if 'managed' in attach_info:
            self.assertIn(attach_info['managed'], ('true', 'false'))

        if CONF.cyborg_pci.expected_managed is not None:
            expected = str(CONF.cyborg_pci.expected_managed).lower()
            self.assertEqual(expected, attach_info.get('managed'))

    @decorators.idempotent_id('1f6ef53b-9c65-4af9-b42f-c23389f7b529')
    @decorators.attr(type='smoke')
    @utils.services('compute', 'network')
    def test_create_delete_server_with_pci_driver_device(self):
        self._run_create_delete_server(**self._lifecycle_params)

    @decorators.idempotent_id('33412e4d-61b9-4cbd-80e0-e03c0dc296cc')
    @utils.services('compute', 'network')
    def test_guest_reboot_with_pci_driver_device(self):
        self._run_guest_reboot(**self._lifecycle_params)

    @decorators.idempotent_id('2da4cd2d-1a58-4347-8f51-98b65e3b853a')
    @utils.services('compute', 'network')
    def test_soft_reboot_server_with_pci_driver_device(self):
        self._run_soft_reboot(**self._lifecycle_params)

    @decorators.idempotent_id('2da914ba-7dd6-45fa-a604-e23e0bcecd59')
    @utils.services('compute', 'network')
    def test_hard_reboot_server_with_pci_driver_device(self):
        self._run_hard_reboot(**self._lifecycle_params)

    @decorators.idempotent_id('b33d085c-8e97-41c1-8eef-6e31adbe06df')
    @utils.services('compute', 'network')
    def test_pause_unpause_server_with_pci_driver_device(self):
        self._run_pause_unpause(**self._lifecycle_params)

    @decorators.idempotent_id('0f74175e-6f02-4769-8f9e-339a57a136a4')
    @utils.services('compute', 'network', 'image')
    def test_snapshot_server_with_pci_driver_device(self):
        self._run_snapshot(**self._lifecycle_params)

    @decorators.idempotent_id('f6193834-bd47-4d81-8f5b-b84aabddd7e9')
    @utils.services('compute', 'network', 'image')
    def test_backup_server_with_pci_driver_device(self):
        self._run_backup(**self._lifecycle_params)

    @decorators.idempotent_id('efab040d-3003-4758-8ded-32a8e9f992bf')
    @utils.services('compute', 'network')
    def test_lock_unlock_server_with_pci_driver_device(self):
        self._run_lock_unlock(**self._lifecycle_params)

    @decorators.idempotent_id('1b5baf1e-b97d-48cf-8ee7-b3e99b407b4c')
    @utils.services('compute', 'network')
    def test_rebuild_server_with_pci_driver_device(self):
        self._run_rebuild(**self._lifecycle_params)

    @decorators.idempotent_id('4d695479-afd5-45f2-a0bd-35a0fe20c1d2')
    @utils.services('compute', 'network', 'image')
    def test_shelve_unshelve_server_with_pci_driver_device(self):
        self._run_shelve_unshelve(**self._lifecycle_params)
