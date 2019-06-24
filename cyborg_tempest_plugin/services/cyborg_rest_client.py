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
from oslo_serialization import jsonutils as json

from tempest import config
from tempest.lib import auth
from tempest.lib.common import rest_client


CONF = config.CONF
LOG = logging.getLogger(__name__)


class CyborgRestClient(rest_client.RestClient):
    """Client class for accessing the cyborg API."""
    DP_URL = '/device_profiles'

    def _response_helper(self, resp, body=None):
        if body:
            body = json.loads(body)
        return rest_client.ResponseBody(resp, body)

    def create_device_profile(self, body):
        body = json.dump_as_bytes(body)
        resp, body = self.post(self.DP_URL, body=body)
        return self._response_helper(resp, body)

    def delete_device_profile(self, name):
        url = self.DP_URL + "/" + name
        resp, body = self.delete(url)
        return self._response_helper(resp, body)

    def list_device_profile(self):
        resp, body = self.get(self.DP_URL)
        return self._response_helper(resp, body)


def get_auth_provider(credentials, scope='project'):
    default_params = {
        'disable_ssl_certificate_validation':
            CONF.identity.disable_ssl_certificate_validation,
        'ca_certs': CONF.identity.ca_certificates_file,
        'trace_requests': CONF.debug.trace_requests
    }

    if isinstance(credentials, auth.KeystoneV3Credentials):
        auth_provider_class, auth_url = \
            auth.KeystoneV3AuthProvider, CONF.identity.uri_v3
    else:
        auth_provider_class, auth_url = \
            auth.KeystoneV2AuthProvider, CONF.identity.uri

    _auth_provider = auth_provider_class(credentials, auth_url,
                                         scope=scope,
                                         **default_params)
    _auth_provider.set_auth()
    return _auth_provider
