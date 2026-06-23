# Copyright 2015
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


from oslo_config import cfg

service_available_group = cfg.OptGroup(
    name="service_available",
    title="Available OpenStack Services"
)

ServiceAvailableGroup = [
    cfg.BoolOpt("cyborg", default=True,
                help="Whether or not cyborg is expected to be available")
]

cyborg_pci_group = cfg.OptGroup(
    name="cyborg_pci",
    title="Cyborg PCI Driver Tempest Plugin Options"
)

CyborgPCIGroup = [
    cfg.StrOpt("device_profile_name",
               default="",
               help="Device profile name used by Cyborg PCI scenario tests."),
    cfg.StrOpt("vendor_id",
               default="",
               help="Expected PCI vendor ID visible in the guest."),
    cfg.StrOpt("product_id",
               default="",
               help="Expected PCI product ID visible in the guest."),
]
