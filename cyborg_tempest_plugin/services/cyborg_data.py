# Copyright 2020 Inspur, Inc.
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

import copy


NORMAL_DEVICE_PROFILE_DATA1 = [{
    "name": "fpga-num-1-dp1",
    "groups": [
        {
            "resources:FPGA": "1",
            "trait:CUSTOM_FAKE_DEVICE": "required"
        }],
    "description": "fpga-num-1-dp1-desc"
    }]

SCENARIO_DEVICE_PROFILE_DATA = [{
    "name": "fpga-num-1-scenario",
    "groups": [
        {
            "resources:FPGA": "1",
            "trait:CUSTOM_FAKE_DEVICE": "required"
        }]
    }]

SERVICE_TOKEN_DEVICE_PROFILE_DATA = [{
    "name": "fpga-svc-token-test",
    "groups": [
        {
            "resources:FPGA": "1",
            "trait:CUSTOM_FAKE_DEVICE": "required"
        }]
    }]

_FAKE_DEVICE_GROUPS = [
    {
        'resources:FPGA': '1',
        'trait:CUSTOM_FAKE_DEVICE': 'required',
    }
]


def make_device_profile_data(name, description=None):
    """Return a single-item DP list with a unique name.

    Use this in API tests instead of the module-level constants
    so that each test creates a DP with a name that cannot
    collide with any other test running concurrently.
    """
    dp = {'name': name, 'groups': copy.deepcopy(_FAKE_DEVICE_GROUPS)}
    if description is not None:
        dp['description'] = description
    return [dp]
