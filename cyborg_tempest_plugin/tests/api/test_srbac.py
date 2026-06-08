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

"""Persona-based RBAC integration tests for the Cyborg API.

These tests exercise the new DocumentedRuleDefault policies introduced
by the consistent-and-secure-rbac blueprint. They are skipped unless
CONF.cyborg_policy.enforce_new_defaults is enabled, so legacy-policy jobs
continue to use their existing coverage. Scope is enforced independently
for every policy that declares ``scope_types``.
"""

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from cyborg_tempest_plugin.tests.api import base

CONF = config.CONF

# Unique ARQ create payload; device_profile_name is filled in per-test.
_ARQ_GROUPS = [
    {
        'resources:FPGA': '1',
        'trait:CUSTOM_FAKE_DEVICE': 'required',
    }
]

_SRBAC_DP_DATA = [
    {
        'name': 'srbac-test-dp',
        'groups': _ARQ_GROUPS,
    }
]


def _arq_body(dp_name):
    return {'device_profile_name': dp_name}


class TestSRBACServiceRole(base.BaseAPITest):
    """Service role can write ARQs.

    The ARQ write policy is ``project_member_or_service``.
    """

    @classmethod
    def skip_checks(cls):
        super(TestSRBACServiceRole, cls).skip_checks()
        if not CONF.cyborg_policy.enforce_new_defaults:
            raise cls.skipException(
                'SRBAC tests require '
                'cyborg_policy.enforce_new_defaults = True')

    @classmethod
    def resource_setup(cls):
        super(TestSRBACServiceRole, cls).resource_setup()
        dp_name = _SRBAC_DP_DATA[0]['name']
        dp_resp = cls.cyborg_admin_client.create_device_profile(
            _SRBAC_DP_DATA)
        cls.addClassResourceCleanup(
            cls.cyborg_admin_client.delete_device_profile,
            dp_name,
        )
        cls._dp_name = dp_resp['name']

    @decorators.idempotent_id('4af35df0-461a-4dab-b2e5-dcec85ce6dcc')
    def test_service_create_and_delete_arq(self):
        """Service role satisfies project_member_or_service on ARQ writes."""
        body = _arq_body(self._dp_name)
        resp = self.cyborg_service_client.create_accelerator_request(body)
        arq_uuid = resp['arqs'][0]['uuid']
        self.addCleanup(
            self.cyborg_service_client.delete_accelerator_request,
            arq_uuid,
        )


class TestSRBACAdminImpliedRoles(base.BaseAPITest):
    """Admin access to project-scoped resources.

    The ARQ write test exercises Keystone's admin-to-member role implication.
    The read policies exercised here have explicit admin alternatives, so
    those tests demonstrate direct admin access rather than implied roles.
    """

    @classmethod
    def skip_checks(cls):
        super(TestSRBACAdminImpliedRoles, cls).skip_checks()
        if not CONF.cyborg_policy.enforce_new_defaults:
            raise cls.skipException(
                'SRBAC tests require '
                'cyborg_policy.enforce_new_defaults = True')

    @classmethod
    def resource_setup(cls):
        super(TestSRBACAdminImpliedRoles, cls).resource_setup()
        dp_name = 'srbac-implied-dp'
        dp_data = [{
            'name': dp_name,
            'groups': _ARQ_GROUPS,
        }]
        dp_resp = cls.cyborg_admin_client.create_device_profile(
            dp_data)
        cls.addClassResourceCleanup(
            cls.cyborg_admin_client.delete_device_profile,
            dp_name,
        )
        cls._dp_name = dp_resp['name']

    @decorators.idempotent_id('7049b127-4d7b-41b0-8730-f4f40f0f1467')
    def test_admin_can_read_arqs(self):
        """Admin is allowed directly by project_reader_or_admin."""
        resp = self.cyborg_admin_client.list_accelerator_request()
        self.assertIn('arqs', resp)

    @decorators.idempotent_id('b0cf2b5c-bb9f-421a-847d-9ba6dd5deb92')
    def test_admin_can_write_arqs(self):
        """Admin passes project_member_or_service via implied member role."""
        body = _arq_body(self._dp_name)
        resp = self.cyborg_admin_client.create_accelerator_request(body)
        arq_uuid = resp['arqs'][0]['uuid']
        self.addCleanup(
            self.cyborg_admin_client.delete_accelerator_request, arq_uuid)

    @decorators.idempotent_id('3ab9e8c0-3493-4f34-af77-dcce42298bb0')
    def test_admin_can_read_devices(self):
        """Admin is allowed directly by project_manager_or_admin."""
        resp = self.cyborg_admin_client.list_devices()
        self.assertIn('devices', resp)

    @decorators.idempotent_id('d8cf8f77-f637-4755-913f-99971eceaa89')
    def test_admin_can_read_deployables(self):
        """Admin is allowed directly by project_manager_or_admin."""
        resp = self.cyborg_admin_client.list_deployables()
        self.assertIn('deployables', resp)

    @decorators.idempotent_id('a1b2c3d4-e5f6-7890-abcd-ef1234567890')
    def test_admin_can_list_attributes(self):
        """Admin is allowed directly by project_manager_or_admin."""
        resp = self.cyborg_admin_client.list_attributes()
        self.assertIn('attributes', resp)

    @decorators.idempotent_id('b2c3d4e5-f6a7-8901-bcde-f12345678901')
    def test_reader_can_list_device_profiles(self):
        """Reader satisfies project_reader_or_admin on device profiles."""
        resp = (
            self.os_project_reader.cyborg_client.list_device_profile())
        self.assertIn('device_profiles', resp)

    @decorators.idempotent_id('c3d4e5f6-a7b8-9012-cdef-123456789012')
    def test_reader_can_list_arqs(self):
        """Reader satisfies project_reader_or_admin on ARQ list."""
        resp = (
            self.os_project_reader.cyborg_client
            .list_accelerator_request())
        self.assertIn('arqs', resp)


class TestSRBACScopeEnforcement(base.BaseAPITest):
    """A system-scoped token cannot access project-scoped Cyborg APIs."""

    credentials = base.BaseAPITest.credentials + ['system_admin']

    @classmethod
    def skip_checks(cls):
        super(TestSRBACScopeEnforcement, cls).skip_checks()
        if not CONF.cyborg_policy.enforce_new_defaults:
            raise cls.skipException(
                'SRBAC tests require '
                'cyborg_policy.enforce_new_defaults = True')

    @classmethod
    def setup_clients(cls):
        super(TestSRBACScopeEnforcement, cls).setup_clients()
        cls.cyborg_system_admin_client = cls._make_cyborg_client(
            cls.os_system_admin)

    @decorators.attr(type=['negative', 'gate'])
    @decorators.idempotent_id('66f071ce-dd76-4594-be98-a5a48d58d578')
    def test_system_admin_cannot_list_devices(self):
        """Scope enforcement rejects a system token on a project API."""
        self.assertRaises(
            lib_exc.Forbidden,
            self.cyborg_system_admin_client.list_devices,
        )
