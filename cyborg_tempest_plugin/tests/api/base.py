# Copyright 2019 Intel, Inc.
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


from oslo_log import log as logging
from tempest import config
from tempest import test

from cyborg_tempest_plugin.services import cyborg_rest_client as client


CONF = config.CONF
LOG = logging.getLogger(__name__)


class BaseAPITest(test.BaseTestCase):
    """Base test class for all Cyborg API tests.

    Provides one CyborgRestClient per Keystone persona and exposes
    canonical persona client attributes that select the appropriate
    client based on whether Cyborg uses the oslo.policy new defaults
    (CONF.cyborg_policy.enforce_new_defaults). Policy scope is always
    enforced when a rule declares ``scope_types``.

    Persona clients available after setup_clients():
      cyborg_admin_client   -- always admin
      cyborg_manager_client -- manager (new) / admin (legacy)
      cyborg_member_client  -- member (new) / admin (legacy)
      cyborg_reader_client  -- reader (new) / admin (legacy)
      cyborg_service_client -- service role

    Persona-specific clients remain available through the corresponding
    os_* managers for tests that intentionally assert cross-persona policy.
    """

    credentials = [
        'primary',
        'admin',
        'project_admin',
        'project_manager',
        'project_member',
        'project_reader',
        ['service_user', 'service'],
    ]

    @classmethod
    def skip_checks(cls):
        super(BaseAPITest, cls).skip_checks()
        if not CONF.service_available.cyborg:
            raise cls.skipException('Cyborg support is required')

    @classmethod
    def _make_cyborg_client(cls, os_manager):
        """Return a CyborgRestClient using the given manager's auth."""
        return client.CyborgRestClient(
            os_manager.auth_provider,
            'accelerator',
            CONF.identity.region,
        )

    @classmethod
    def setup_clients(cls):
        super(BaseAPITest, cls).setup_clients()

        cls.cyborg_admin_client = cls._make_cyborg_client(cls.os_admin)
        cls.cyborg_service_client = (
            cls._make_cyborg_client(cls.os_service_user))
        cls.os_admin.cyborg_client = cls.cyborg_admin_client

        # Build persona-specific clients for tests that intentionally
        # assert cross-persona policy behavior.
        project_admin_client = cls._make_cyborg_client(cls.os_project_admin)
        project_manager_client = (
            cls._make_cyborg_client(cls.os_project_manager))
        project_member_client = (
            cls._make_cyborg_client(cls.os_project_member))
        project_reader_client = (
            cls._make_cyborg_client(cls.os_project_reader))
        cls.os_project_admin.cyborg_client = project_admin_client
        cls.os_project_manager.cyborg_client = project_manager_client
        cls.os_project_member.cyborg_client = project_member_client
        cls.os_project_reader.cyborg_client = project_reader_client

        # Canonical persona clients. When the new defaults are active,
        # each client uses the minimum persona required by the policy.
        # In legacy mode, they fall back to admin so existing jobs keep
        # passing unchanged.
        if CONF.cyborg_policy.enforce_new_defaults:
            cls.cyborg_reader_client = project_reader_client
            cls.cyborg_member_client = project_member_client
            cls.cyborg_manager_client = project_manager_client
        else:
            cls.cyborg_reader_client = cls.cyborg_admin_client
            cls.cyborg_member_client = cls.cyborg_admin_client
            cls.cyborg_manager_client = cls.cyborg_admin_client

    @classmethod
    def setup_credentials(cls):
        super(BaseAPITest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        super(BaseAPITest, cls).resource_setup()

    @classmethod
    def resource_cleanup(cls):
        super(BaseAPITest, cls).resource_cleanup()
