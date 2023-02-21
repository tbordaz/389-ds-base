# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2019 RED Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ----

import pytest, os

import logging
import ldap
from lib389.backend import Backends, Backend
from lib389.mappingTree import MappingTrees
from lib389.configurations.sample import create_base_domain
from  ldap.extop import ExtendedRequest
from pyasn1.type import namedtype, univ
from pyasn1.codec.ber import encoder, decoder
from lib389.utils import ensure_bytes
from ldap.extop import ExtendedRequest, ExtendedResponse
from pyasn1.type import namedtype, univ
from pyasn1.codec.ber import encoder, decoder
from lib389 import Entry

from lib389._constants import DEFAULT_SUFFIX, PW_DM
from lib389.topologies import topology_st as topo

from lib389.idm.user import UserAccount, UserAccounts
from lib389.idm.account import Accounts

pytestmark = pytest.mark.tier0
log = logging.getLogger(__name__)

class SlapiMemberofRequestValue(univ.Sequence):
    pass

class SlapiMemberofRequest(ExtendedRequest):
    def __init__(self, requestValidLifeTime=0):
        self.requestName = '2.3.4.5.113730.6.7.1'

    def encodedRequestValue(self):
        v = SlapiMemberofRequestValue()
        return encoder.encode(v)

def _check_res_vs_expected(msg, res, expected):
    log.info("Checking %s expecting %d entries" % (msg, len(expected)))
    assert len(expected) == len(res)
    expected_str_lower = []
    for i in expected:
        expected_str_lower.append(str(i).lower())

    res_str_lower = []
    for i in res:
        res_str_lower.append(str(i).lower())

    for i in expected_str_lower:
        log.info("Check that %s is present" % (i))
        assert i in res_str_lower

EMPTY_RESULT="no error msg"

def _extop_test_slapi_member(server, dn, relation):
    value = univ.OctetString(dn)
    value_encoded = encoder.encode(value)

    extop = ExtendedRequest(requestName = '2.3.4.5.113730.6.7.1', requestValue=value_encoded)
    (oid_response, res) = server.extop_s(extop)
    d1, d2 = decoder.decode(res)
    log.info("The entries refering to %s as %s are:" % (dn, relation))
    for i in d1:
        log.info(" - %s" % i)
    return d1


def replace_manager(server, dn, managers):
    mod = [(ldap.MOD_REPLACE, 'manager', managers)]
    server.modify_s(dn, mod)

def add_entry(server, uid, manager=None, subtree=None):
    if (subtree):
        dn = 'uid=%s,ou=%s,ou=People,%s' % (uid, subtree, DEFAULT_SUFFIX)
    else:
        dn = 'uid=%s,ou=People,%s' % (uid, DEFAULT_SUFFIX)
    server.add_s(Entry((dn, {'objectclass': 'top person extensibleObject'.split(),
                             'uid': uid,
                             'cn':  uid,
                             'sn': uid})))
    if manager:
        replace_manager(server, dn, manager)
    return dn

def test_slapi_memberof_simple(topo, request):
    """
    Test that management hierarchy (manager) is computed with slapi_member
    with following parameters
                 membership attribute: 'manager'
                 span over all backends: 'on'
                 skip nesting membership: 'off'
                 computation mode: recompute
                 Scope: DEFAULT_SUFFIX
                 ExcludeScope: None
                 Maximum return entries: None

    :id: 4c2595eb-a947-4c0b-996c-e499db67d11a
    :setup: Standalone instance
    :steps:
        1. provision a set of entry
        2. configure test_slapi_memberof as described above
        3. check computed membership vs expected result
    :expectedresults:
        1. Operation should  succeed
        2. Operation should  succeed
        3. Operation should  succeed

    DIT is :
    e_1_parent_0
        e_1_parent_1_0
            e_1_parent_1_1_0
                e_1_parent_1_1_1_0
                e_2_parent_1_1_1_0
                e_3_parent_1_1_1_0
                e_4_parent_1_1_1_0
                e_5_parent_1_1_1_0
            e_2_parent_1_1_0
        e_2_parent_1_0
            e_1_parent_2_1_0
            e_2_parent_2_1_0
                e_1_parent_2_2_1_0
            e_3_parent_2_1_0
            e_4_parent_2_1_0
    e_2_parent_0
        e_1_parent_2_0
        e_2_parent_2_0
        e_3_parent_2_0
        e_4_parent_2_0
    e_3_parent_0
        e_1_parent_3_0
            e_1_parent_1_3_0
                e_1_parent_1_1_3_0
                    e_1_parent_1_1_1_3_0
    """
    user = UserAccounts(topo.standalone, DEFAULT_SUFFIX)

    # First subtree
    e_1_parent_0 = add_entry(topo.standalone, uid="e_1_parent_0")

    e_1_parent_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_1_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_2_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_3_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_3_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_4_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_4_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_5_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_5_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])

    e_2_parent_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_2_parent_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_2_parent_2_1_0 = add_entry(topo.standalone, uid="e_2_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_1_parent_2_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_2_1_0", manager=[ensure_bytes(e_2_parent_2_1_0)])
    e_3_parent_2_1_0 = add_entry(topo.standalone, uid="e_3_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_4_parent_2_1_0 = add_entry(topo.standalone, uid="e_4_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])

    # 2nd subtree
    e_2_parent_0 = add_entry(topo.standalone, uid="e_2_parent_0")

    e_1_parent_2_0 = add_entry(topo.standalone, uid="e_1_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_2_parent_2_0 = add_entry(topo.standalone, uid="e_2_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_3_parent_2_0 = add_entry(topo.standalone, uid="e_3_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_4_parent_2_0 = add_entry(topo.standalone, uid="e_4_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])

    # third subtree
    e_3_parent_0 = add_entry(topo.standalone, uid="e_3_parent_0")

    e_1_parent_3_0 = add_entry(topo.standalone, uid="e_1_parent_3_0", manager=[ensure_bytes(e_3_parent_0)])

    e_1_parent_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_3_0", manager=[ensure_bytes(e_1_parent_3_0)])

    e_1_parent_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_3_0)])

    e_1_parent_1_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_1_3_0)])

    dn_config = 'cn=test_slapi_memberof,cn=plugins,cn=config'
    topo.standalone.add_s(Entry((dn_config, {'objectclass': 'top nsSlapdPlugin extensibleObject'.split(),
                             'cn': 'test_slapi_memberof',
                             'nsslapd-pluginPath': 'libtest_slapi_memberof-plugin',
                             'nsslapd-pluginInitfunc': 'test_slapi_memberof_init',
                             'nsslapd-pluginType': 'extendedop',
                             'nsslapd-pluginEnabled': 'on',
                             'nsslapd-plugin-depends-on-type': 'database',
                             'nsslapd-pluginId': 'test_slapi_memberof-plugin',
                             'slapimemberOfMemberDN': 'uid=test_user_11,ou=People,dc=example,dc=com',
                             'slapimemberOfGroupAttr': 'manager',
                             'slapimemberOfAttr': 'memberof',
                             'slapimemberOfAllBackends': 'on',
                             'slapimemberOfSkipNested': 'off',
                             'slapimemberOfEntryScope': DEFAULT_SUFFIX,
                             'slapimemberOfMaxGroup': '0',
                             'nsslapd-pluginVersion': '2.3.2.202302131418git0e190fc3d',
                             'nsslapd-pluginVendor': '389 Project',
                             'nsslapd-pluginDescription': 'test_slapi_memberof extended operation plugin'})))
    topo.standalone.restart()

    # Check the first subtree
    expected = [ e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0, e_2_parent_1_0, e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_0, relation="manager")
    _check_res_vs_expected("first subtree", res, expected)

    # Check the second subtree
    expected = [e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_0, relation="manager")
    _check_res_vs_expected("second subtree", res, expected)

    # Check the third subtree
    expected = [e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_3_parent_0, relation="manager")
    _check_res_vs_expected("third subtree", res, expected)

    # check e_1_parent_1_0
    expected = [e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_0", res, expected)

    # check e_1_parent_1_1_0
    expected = [e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_0", res, expected)

    # check e_2_parent_1_1_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_1_0", res, expected)

    # check e_2_parent_1_0
    expected = [e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_0", res, expected)

    # check e_2_parent_2_1_0
    expected = [e_1_parent_2_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_2_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_2_1_0", res, expected)

    # Check e_1_parent_3_0
    expected = [e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_3_0", res, expected)

    # Check e_1_parent_1_3_0
    expected = [e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_3_0", res, expected)

    # Check e_1_parent_1_1_3_0
    expected = [e_1_parent_1_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_3_0", res, expected)

    # Check e_1_parent_1_1_1_3_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_1_3_0", res, expected)

    def fin():
        entries = [e_1_parent_0, e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0, e_2_parent_1_0, e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0, e_2_parent_0, e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0, e_3_parent_0, e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
        for entry in entries:
            topo.standalone.delete_s(entry)
        topo.standalone.delete_s(dn_config)

    request.addfinalizer(fin)

def test_slapi_memberof_allbackends_on(topo, request):
    """
    Test that management hierarchy (manager) is computed with slapi_member
    It exists several backends and manager relationship cross those backends
    with following parameters
                 membership attribute: 'manager'
                 span over all backends: 'on'  <----
                 skip nesting membership: 'off'
                 computation mode: recompute
                 Scope: DEFAULT_SUFFIX
                 ExcludeScope: None
                 Maximum return entries: None

    :id: 910c43a0-04ae-48f1-9e3c-6d97ba5bcb71
    :setup: Standalone instance
    :steps:
        1. create a second backend with foo_bar entry
        2. provision a set of entries in default backend with foo_bar being
           manager of entry e_1_parent_1_1_1_3_0 that is in default backend
        3. configure test_slapi_memberof as described above
        4. check computed membership vs expected result
           slapi_memberof(foo_bar, "manager") -> e_1_parent_1_1_1_3_0
    :expectedresults:
        1. Operation should  succeed
        2. Operation should  succeed
        3. Operation should  succeed
        4. Operation should  succeed
    e_1_parent_0
        e_1_parent_1_0
            e_1_parent_1_1_0
                e_1_parent_1_1_1_0
                e_2_parent_1_1_1_0
                e_3_parent_1_1_1_0
                e_4_parent_1_1_1_0
                e_5_parent_1_1_1_0
            e_2_parent_1_1_0
        e_2_parent_1_0
            e_1_parent_2_1_0
            e_2_parent_2_1_0
                e_1_parent_2_2_1_0
            e_3_parent_2_1_0
            e_4_parent_2_1_0
    e_2_parent_0
        e_1_parent_2_0
        e_2_parent_2_0
        e_3_parent_2_0
        e_4_parent_2_0
    e_3_parent_0
        e_1_parent_3_0
            e_1_parent_1_3_0
                e_1_parent_1_1_3_0
                    e_1_parent_1_1_1_3_0
    """
    # create a second backend
    second_suffix='dc=foo,dc=bar'
    be_name='fooBar'
    be1 = Backend(topo.standalone)
    be1.create(properties={
            'cn': be_name,
            'nsslapd-suffix': second_suffix,
        },
    )
    # Create the domain entry
    create_base_domain(topo.standalone, second_suffix)
    rdn='foo_bar'
    dn_entry_foo_bar='uid=%s,%s' % (rdn, second_suffix)
    topo.standalone.add_s(Entry((dn_entry_foo_bar, {'objectclass': 'top person extensibleObject'.split(),
                             'uid': rdn,
                             'cn':  rdn,
                             'sn': rdn})))

    user = UserAccounts(topo.standalone, DEFAULT_SUFFIX)

    # First subtree
    e_1_parent_0 = add_entry(topo.standalone, uid="e_1_parent_0")

    e_1_parent_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_1_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_2_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_3_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_3_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_4_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_4_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_5_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_5_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])

    e_2_parent_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_2_parent_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_2_parent_2_1_0 = add_entry(topo.standalone, uid="e_2_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_1_parent_2_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_2_1_0", manager=[ensure_bytes(e_2_parent_2_1_0)])
    e_3_parent_2_1_0 = add_entry(topo.standalone, uid="e_3_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_4_parent_2_1_0 = add_entry(topo.standalone, uid="e_4_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])

    # 2nd subtree
    e_2_parent_0 = add_entry(topo.standalone, uid="e_2_parent_0")

    e_1_parent_2_0 = add_entry(topo.standalone, uid="e_1_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_2_parent_2_0 = add_entry(topo.standalone, uid="e_2_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_3_parent_2_0 = add_entry(topo.standalone, uid="e_3_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_4_parent_2_0 = add_entry(topo.standalone, uid="e_4_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])

    # third subtree
    e_3_parent_0 = add_entry(topo.standalone, uid="e_3_parent_0")

    e_1_parent_3_0 = add_entry(topo.standalone, uid="e_1_parent_3_0", manager=[ensure_bytes(e_3_parent_0)])

    e_1_parent_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_3_0", manager=[ensure_bytes(e_1_parent_3_0)])

    e_1_parent_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_3_0)])

    e_1_parent_1_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_1_3_0)])

    # make foo_bar entry manager of e_1_parent_1_1_1_3_0
    replace_manager(topo.standalone, e_1_parent_1_1_1_3_0, [ensure_bytes(dn_entry_foo_bar)])

    dn_config = 'cn=test_slapi_memberof,cn=plugins,cn=config'
    topo.standalone.add_s(Entry((dn_config, {'objectclass': 'top nsSlapdPlugin extensibleObject'.split(),
                             'cn': 'test_slapi_memberof',
                             'nsslapd-pluginPath': 'libtest_slapi_memberof-plugin',
                             'nsslapd-pluginInitfunc': 'test_slapi_memberof_init',
                             'nsslapd-pluginType': 'extendedop',
                             'nsslapd-pluginEnabled': 'on',
                             'nsslapd-plugin-depends-on-type': 'database',
                             'nsslapd-pluginId': 'test_slapi_memberof-plugin',
                             'slapimemberOfMemberDN': 'uid=test_user_11,ou=People,dc=example,dc=com',
                             'slapimemberOfGroupAttr': 'manager',
                             'slapimemberOfAttr': 'memberof',
                             'slapimemberOfAllBackends': 'on',
                             'slapimemberOfSkipNested': 'off',
                             'slapimemberOfEntryScope': [DEFAULT_SUFFIX, second_suffix],
                             'slapimemberOfMaxGroup': '0',
                             'nsslapd-pluginVersion': '2.3.2.202302131418git0e190fc3d',
                             'nsslapd-pluginVendor': '389 Project',
                             'nsslapd-pluginDescription': 'test_slapi_memberof extended operation plugin'})))
    topo.standalone.restart()

    # Check the first subtree
    expected = [ e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0, e_2_parent_1_0, e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_0, relation="manager")
    _check_res_vs_expected("first subtree", res, expected)

    # Check the second subtree
    expected = [e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_0, relation="manager")
    _check_res_vs_expected("second subtree", res, expected)

    # Check the third subtree
    expected = [e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_3_parent_0, relation="manager")
    _check_res_vs_expected("third subtree", res, expected)

    # check e_1_parent_1_0
    expected = [e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_0", res, expected)

    # check e_1_parent_1_1_0
    expected = [e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_0", res, expected)

    # check e_2_parent_1_1_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_1_0", res, expected)

    # check e_2_parent_1_0
    expected = [e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_0", res, expected)

    # check e_2_parent_2_1_0
    expected = [e_1_parent_2_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_2_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_2_1_0", res, expected)

    # Check e_1_parent_3_0
    expected = [e_1_parent_1_3_0, e_1_parent_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_3_0", res, expected)

    # Check e_1_parent_1_3_0
    expected = [e_1_parent_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_3_0", res, expected)

    # Check e_1_parent_1_1_3_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_3_0", res, expected)

    # Check e_1_parent_1_1_1_3_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_1_3_0", res, expected)

    # Check dn_entry_foo_bar
    expected = [e_1_parent_1_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=dn_entry_foo_bar, relation="manager")
    _check_res_vs_expected("organisation reporting to dn_entry_foo_bar", res, expected)


    def fin():
        entries = [e_1_parent_0, e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0, e_2_parent_1_0, e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0, e_2_parent_0, e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0, e_3_parent_0, e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
        for entry in entries:
            topo.standalone.delete_s(entry)
        topo.standalone.delete_s(dn_config)
        topo.standalone.delete_s(dn_entry_foo_bar)
        be1.delete()

    request.addfinalizer(fin)

def test_slapi_memberof_allbackends_off(topo, request):
    """
    Test that management hierarchy (manager) is computed with slapi_member
    It exists several backends and manager relationship cross those backends
    with following parameters
                 membership attribute: 'manager'
                 span over all backends: 'off'  <----
                 skip nesting membership: 'off'
                 computation mode: recompute
                 Scope: DEFAULT_SUFFIX
                 ExcludeScope: None
                 Maximum return entries: None

    :id: 56fb0c16-8086-429b-adf0-fff0eb8e121e
    :setup: Standalone instance
    :steps:
        1. create a second backend with foo_bar entry
        2. provision a set of entries in default backend with foo_bar being
           manager of entry e_1_parent_1_1_1_3_0 that is in default backend
        3. configure test_slapi_memberof as described above
        4. check computed membership vs expected result
           slapi_memberof(foo_bar, "manager") NOT -> e_1_parent_1_1_1_3_0
    :expectedresults:
        1. Operation should  succeed
        2. Operation should  succeed
        3. Operation should  succeed
        4. Operation should  succeed
    e_1_parent_0
        e_1_parent_1_0
            e_1_parent_1_1_0
                e_1_parent_1_1_1_0
                e_2_parent_1_1_1_0
                e_3_parent_1_1_1_0
                e_4_parent_1_1_1_0
                e_5_parent_1_1_1_0
            e_2_parent_1_1_0
        e_2_parent_1_0
            e_1_parent_2_1_0
            e_2_parent_2_1_0
                e_1_parent_2_2_1_0
            e_3_parent_2_1_0
            e_4_parent_2_1_0
    e_2_parent_0
        e_1_parent_2_0
        e_2_parent_2_0
        e_3_parent_2_0
        e_4_parent_2_0
    e_3_parent_0
        e_1_parent_3_0
            e_1_parent_1_3_0
                e_1_parent_1_1_3_0
                    e_1_parent_1_1_1_3_0
    """
    # Create second backend
    second_suffix='dc=foo,dc=bar'
    be_name='fooBar'
    be1 = Backend(topo.standalone)
    be1.create(properties={
            'cn': be_name,
            'nsslapd-suffix': second_suffix,
        },
    )
    # Create the domain entry
    create_base_domain(topo.standalone, second_suffix)
    rdn='foo_bar'
    dn_entry_foo_bar='uid=%s,%s' % (rdn, second_suffix)
    topo.standalone.add_s(Entry((dn_entry_foo_bar, {'objectclass': 'top person extensibleObject'.split(),
                             'uid': rdn,
                             'cn':  rdn,
                             'sn': rdn})))

    user = UserAccounts(topo.standalone, DEFAULT_SUFFIX)

    # First subtree
    e_1_parent_0 = add_entry(topo.standalone, uid="e_1_parent_0")

    e_1_parent_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_1_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_2_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_3_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_3_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_4_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_4_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_5_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_5_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])

    e_2_parent_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_2_parent_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_2_parent_2_1_0 = add_entry(topo.standalone, uid="e_2_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_1_parent_2_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_2_1_0", manager=[ensure_bytes(e_2_parent_2_1_0)])
    e_3_parent_2_1_0 = add_entry(topo.standalone, uid="e_3_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_4_parent_2_1_0 = add_entry(topo.standalone, uid="e_4_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])

    # 2nd subtree
    e_2_parent_0 = add_entry(topo.standalone, uid="e_2_parent_0")

    e_1_parent_2_0 = add_entry(topo.standalone, uid="e_1_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_2_parent_2_0 = add_entry(topo.standalone, uid="e_2_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_3_parent_2_0 = add_entry(topo.standalone, uid="e_3_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_4_parent_2_0 = add_entry(topo.standalone, uid="e_4_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])

    # third subtree
    e_3_parent_0 = add_entry(topo.standalone, uid="e_3_parent_0")

    e_1_parent_3_0 = add_entry(topo.standalone, uid="e_1_parent_3_0", manager=[ensure_bytes(e_3_parent_0)])

    e_1_parent_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_3_0", manager=[ensure_bytes(e_1_parent_3_0)])

    e_1_parent_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_3_0)])

    e_1_parent_1_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_1_3_0)])

    # make foo_bar entry manager of e_1_parent_1_1_1_3_0
    replace_manager(topo.standalone, e_1_parent_1_1_1_3_0, [ensure_bytes(dn_entry_foo_bar)])

    dn_config = 'cn=test_slapi_memberof,cn=plugins,cn=config'
    topo.standalone.add_s(Entry((dn_config, {'objectclass': 'top nsSlapdPlugin extensibleObject'.split(),
                             'cn': 'test_slapi_memberof',
                             'nsslapd-pluginPath': 'libtest_slapi_memberof-plugin',
                             'nsslapd-pluginInitfunc': 'test_slapi_memberof_init',
                             'nsslapd-pluginType': 'extendedop',
                             'nsslapd-pluginEnabled': 'on',
                             'nsslapd-plugin-depends-on-type': 'database',
                             'nsslapd-pluginId': 'test_slapi_memberof-plugin',
                             'slapimemberOfMemberDN': 'uid=test_user_11,ou=People,dc=example,dc=com',
                             'slapimemberOfGroupAttr': 'manager',
                             'slapimemberOfAttr': 'memberof',
                             'slapimemberOfAllBackends': 'off',
                             'slapimemberOfSkipNested': 'off',
                             'slapimemberOfEntryScope': [DEFAULT_SUFFIX, second_suffix],
                             'slapimemberOfMaxGroup': '0',
                             'nsslapd-pluginVersion': '2.3.2.202302131418git0e190fc3d',
                             'nsslapd-pluginVendor': '389 Project',
                             'nsslapd-pluginDescription': 'test_slapi_memberof extended operation plugin'})))
    topo.standalone.restart()

    # Check the first subtree
    expected = [ e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0, e_2_parent_1_0, e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_0, relation="manager")
    _check_res_vs_expected("first subtree", res, expected)

    # Check the second subtree
    expected = [e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_0, relation="manager")
    _check_res_vs_expected("second subtree", res, expected)

    # Check the third subtree
    expected = [e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_3_parent_0, relation="manager")
    _check_res_vs_expected("third subtree", res, expected)

    # check e_1_parent_1_0
    expected = [e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_0", res, expected)

    # check e_1_parent_1_1_0
    expected = [e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_0", res, expected)

    # check e_2_parent_1_1_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_1_0", res, expected)

    # check e_2_parent_1_0
    expected = [e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_0", res, expected)

    # check e_2_parent_2_1_0
    expected = [e_1_parent_2_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_2_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_2_1_0", res, expected)

    # Check e_1_parent_3_0
    expected = [e_1_parent_1_3_0, e_1_parent_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_3_0", res, expected)

    # Check e_1_parent_1_3_0
    expected = [e_1_parent_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_3_0", res, expected)

    # Check e_1_parent_1_1_3_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_3_0", res, expected)

    # Check e_1_parent_1_1_1_3_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_1_3_0", res, expected)

    # Check dn_entry_foo_bar is not manager of e_1_parent_1_1_1_3_0 because slapimemberOfAllBackends=off
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=dn_entry_foo_bar, relation="manager")
    _check_res_vs_expected("organisation reporting to dn_entry_foo_bar", res, expected)


    def fin():
        entries = [e_1_parent_0, e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0, e_2_parent_1_0, e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0, e_2_parent_0, e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0, e_3_parent_0, e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
        for entry in entries:
            topo.standalone.delete_s(entry)
        topo.standalone.delete_s(dn_config)
        topo.standalone.delete_s(dn_entry_foo_bar)
        be1.delete()

    request.addfinalizer(fin)


def test_slapi_memberof_memberattr(topo, request):
    """
    Test that membership hierarchy (member) is computed with slapi_member
    the membership is done with 'manager' attribute but slapi_memberof
    called with 'member' attribute. As there is no 'member' then 
    membership returns empty_results
    with following parameters
                 membership attribute: 'member'  <----
                 span over all backends: 'on'
                 skip nesting membership: 'off'
                 computation mode: recompute
                 Scope: DEFAULT_SUFFIX
                 ExcludeScope: None
                 Maximum return entries: None

    :id: 373f7f65-185f-4b06-a0a5-3e23692b87f1
    :setup: Standalone instance
    :steps:
        1. provision a set of entries in default backend
           with membership using 'manager'
        3. configure test_slapi_memberof as described above
           so checking membership using 'member'
        4. check computed membership vs expected result
           all empty_result because no entry has 'member'
    :expectedresults:
        1. Operation should  succeed
        2. Operation should  succeed
        3. Operation should  succeed
        4. Operation should  succeed
    e_1_parent_0
        e_1_parent_1_0
            e_1_parent_1_1_0
                e_1_parent_1_1_1_0
                e_2_parent_1_1_1_0
                e_3_parent_1_1_1_0
                e_4_parent_1_1_1_0
                e_5_parent_1_1_1_0
            e_2_parent_1_1_0
        e_2_parent_1_0
            e_1_parent_2_1_0
            e_2_parent_2_1_0
                e_1_parent_2_2_1_0
            e_3_parent_2_1_0
            e_4_parent_2_1_0
    e_2_parent_0
        e_1_parent_2_0
        e_2_parent_2_0
        e_3_parent_2_0
        e_4_parent_2_0
    e_3_parent_0
        e_1_parent_3_0
            e_1_parent_1_3_0
                e_1_parent_1_1_3_0
                    e_1_parent_1_1_1_3_0
    """
    user = UserAccounts(topo.standalone, DEFAULT_SUFFIX)

    # First subtree
    e_1_parent_0 = add_entry(topo.standalone, uid="e_1_parent_0")

    e_1_parent_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_1_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_2_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_3_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_3_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_4_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_4_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_5_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_5_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])

    e_2_parent_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_2_parent_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_2_parent_2_1_0 = add_entry(topo.standalone, uid="e_2_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_1_parent_2_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_2_1_0", manager=[ensure_bytes(e_2_parent_2_1_0)])
    e_3_parent_2_1_0 = add_entry(topo.standalone, uid="e_3_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_4_parent_2_1_0 = add_entry(topo.standalone, uid="e_4_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])

    # 2nd subtree
    e_2_parent_0 = add_entry(topo.standalone, uid="e_2_parent_0")

    e_1_parent_2_0 = add_entry(topo.standalone, uid="e_1_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_2_parent_2_0 = add_entry(topo.standalone, uid="e_2_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_3_parent_2_0 = add_entry(topo.standalone, uid="e_3_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_4_parent_2_0 = add_entry(topo.standalone, uid="e_4_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])

    # third subtree
    e_3_parent_0 = add_entry(topo.standalone, uid="e_3_parent_0")

    e_1_parent_3_0 = add_entry(topo.standalone, uid="e_1_parent_3_0", manager=[ensure_bytes(e_3_parent_0)])

    e_1_parent_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_3_0", manager=[ensure_bytes(e_1_parent_3_0)])

    e_1_parent_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_3_0)])

    e_1_parent_1_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_1_3_0)])

    dn_config = 'cn=test_slapi_memberof,cn=plugins,cn=config'
    topo.standalone.add_s(Entry((dn_config, {'objectclass': 'top nsSlapdPlugin extensibleObject'.split(),
                             'cn': 'test_slapi_memberof',
                             'nsslapd-pluginPath': 'libtest_slapi_memberof-plugin',
                             'nsslapd-pluginInitfunc': 'test_slapi_memberof_init',
                             'nsslapd-pluginType': 'extendedop',
                             'nsslapd-pluginEnabled': 'on',
                             'nsslapd-plugin-depends-on-type': 'database',
                             'nsslapd-pluginId': 'test_slapi_memberof-plugin',
                             'slapimemberOfMemberDN': 'uid=test_user_11,ou=People,dc=example,dc=com',
                             'slapimemberOfGroupAttr': 'member',
                             'slapimemberOfAttr': 'memberof',
                             'slapimemberOfAllBackends': 'on',
                             'slapimemberOfSkipNested': 'off',
                             'slapimemberOfEntryScope': DEFAULT_SUFFIX,
                             'slapimemberOfMaxGroup': '0',
                             'nsslapd-pluginVersion': '2.3.2.202302131418git0e190fc3d',
                             'nsslapd-pluginVendor': '389 Project',
                             'nsslapd-pluginDescription': 'test_slapi_memberof extended operation plugin'})))
    topo.standalone.restart()

    # Check the first subtree
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_0, relation="manager")
    _check_res_vs_expected("first subtree", res, expected)

    # Check the second subtree
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_0, relation="manager")
    _check_res_vs_expected("second subtree", res, expected)

    # Check the third subtree
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_3_parent_0, relation="manager")
    _check_res_vs_expected("third subtree", res, expected)

    # check e_1_parent_1_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_0", res, expected)

    # check e_1_parent_1_1_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_0", res, expected)

    # check e_2_parent_1_1_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_1_0", res, expected)

    # check e_2_parent_1_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_0", res, expected)

    # check e_2_parent_2_1_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_2_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_2_1_0", res, expected)

    # Check e_1_parent_3_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_3_0", res, expected)

    # Check e_1_parent_1_3_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_3_0", res, expected)

    # Check e_1_parent_1_1_3_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_3_0", res, expected)

    # Check e_1_parent_1_1_1_3_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_1_3_0", res, expected)

    def fin():
        entries = [e_1_parent_0, e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0, e_2_parent_1_0, e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0, e_2_parent_0, e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0, e_3_parent_0, e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
        for entry in entries:
            topo.standalone.delete_s(entry)
        topo.standalone.delete_s(dn_config)

    request.addfinalizer(fin)


def test_slapi_memberof_scope(topo, request):
    """
    Test that membership hierarchy (member) is computed with slapi_member
    Only entries in the subtree scope (e_2_parent_1_0) gets valid
    computation of the membership
    with following parameters
                 membership attribute: 'manager'
                 span over all backends: 'on'
                 skip nesting membership: 'off'
                 computation mode: recompute
                 Scope: ou=subtree,ou=People,dc=example,dc=com  <----
                 ExcludeScope: None
                 Maximum return entries: None

    :id: 6c7587e0-0bc4-4847-b403-773d7314aa31
    :setup: Standalone instance
    :steps:
        1. provision a set of entries in default backend
        2. configure test_slapi_memberof as described above
           so only entries under e_2_parent_1_0 are taken into
           consideration
        3. check computed membership vs expected result
           Only entries under e_2_parent_1_0 get no empty results
    :expectedresults:
        1. Operation should  succeed
        2. Operation should  succeed
        3. Operation should  succeed
    e_1_parent_0
        e_1_parent_1_0
            e_1_parent_1_1_0
                e_1_parent_1_1_1_0
                e_2_parent_1_1_1_0
                e_3_parent_1_1_1_0
                e_4_parent_1_1_1_0
                e_5_parent_1_1_1_0
            e_2_parent_1_1_0
        e_2_parent_1_0 (subtree)                <----
            e_1_parent_2_1_0 (subtree)          <----
            e_2_parent_2_1_0 (subtree)          <----
                e_1_parent_2_2_1_0 (subtree)    <----
            e_3_parent_2_1_0 (subtree)          <----
            e_4_parent_2_1_0 (subtree)          <----
    e_2_parent_0
        e_1_parent_2_0
        e_2_parent_2_0
        e_3_parent_2_0
        e_4_parent_2_0
    e_3_parent_0
        e_1_parent_3_0
            e_1_parent_1_3_0
                e_1_parent_1_1_3_0
                    e_1_parent_1_1_1_3_0
    """

    subtree="subtree"
    dn_subtree = 'ou=%s,ou=People,%s' % (subtree, DEFAULT_SUFFIX)
    topo.standalone.add_s(Entry((dn_subtree, {'objectclass': 'top organizationalunit'.split(),
                                              'ou': subtree})))
    # First subtree
    e_1_parent_0 = add_entry(topo.standalone, uid="e_1_parent_0")

    e_1_parent_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_1_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_2_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_3_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_3_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_4_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_4_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_5_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_5_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])

    e_2_parent_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_2_parent_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_0", manager=[ensure_bytes(e_1_parent_0)], subtree=subtree)

    e_1_parent_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)], subtree=subtree)
    e_2_parent_2_1_0 = add_entry(topo.standalone, uid="e_2_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)], subtree=subtree)
    e_1_parent_2_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_2_1_0", manager=[ensure_bytes(e_2_parent_2_1_0)], subtree=subtree)
    e_3_parent_2_1_0 = add_entry(topo.standalone, uid="e_3_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)], subtree=subtree)
    e_4_parent_2_1_0 = add_entry(topo.standalone, uid="e_4_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)], subtree=subtree)

    # 2nd subtree
    e_2_parent_0 = add_entry(topo.standalone, uid="e_2_parent_0")

    e_1_parent_2_0 = add_entry(topo.standalone, uid="e_1_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_2_parent_2_0 = add_entry(topo.standalone, uid="e_2_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_3_parent_2_0 = add_entry(topo.standalone, uid="e_3_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_4_parent_2_0 = add_entry(topo.standalone, uid="e_4_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])

    # third subtree
    e_3_parent_0 = add_entry(topo.standalone, uid="e_3_parent_0")

    e_1_parent_3_0 = add_entry(topo.standalone, uid="e_1_parent_3_0", manager=[ensure_bytes(e_3_parent_0)])

    e_1_parent_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_3_0", manager=[ensure_bytes(e_1_parent_3_0)])

    e_1_parent_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_3_0)])

    e_1_parent_1_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_1_3_0)])

    dn_config = 'cn=test_slapi_memberof,cn=plugins,cn=config'
    topo.standalone.add_s(Entry((dn_config, {'objectclass': 'top nsSlapdPlugin extensibleObject'.split(),
                             'cn': 'test_slapi_memberof',
                             'nsslapd-pluginPath': 'libtest_slapi_memberof-plugin',
                             'nsslapd-pluginInitfunc': 'test_slapi_memberof_init',
                             'nsslapd-pluginType': 'extendedop',
                             'nsslapd-pluginEnabled': 'on',
                             'nsslapd-plugin-depends-on-type': 'database',
                             'nsslapd-pluginId': 'test_slapi_memberof-plugin',
                             'slapimemberOfMemberDN': 'uid=test_user_11,ou=People,dc=example,dc=com',
                             'slapimemberOfGroupAttr': 'manager',
                             'slapimemberOfAttr': 'memberof',
                             'slapimemberOfAllBackends': 'on',
                             'slapimemberOfSkipNested': 'off',
                             'slapimemberOfEntryScope': dn_subtree,
                             'slapimemberOfMaxGroup': '0',
                             'nsslapd-pluginVersion': '2.3.2.202302131418git0e190fc3d',
                             'nsslapd-pluginVendor': '389 Project',
                             'nsslapd-pluginDescription': 'test_slapi_memberof extended operation plugin'})))
    topo.standalone.restart()

    # Check the first subtree
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_0, relation="manager")
    _check_res_vs_expected("first subtree", res, expected)

    # Check the second subtree
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_0, relation="manager")
    _check_res_vs_expected("second subtree", res, expected)

    # Check the third subtree
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_3_parent_0, relation="manager")
    _check_res_vs_expected("third subtree", res, expected)

    # check e_1_parent_1_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_0", res, expected)

    # check e_1_parent_1_1_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_0", res, expected)

    # check e_2_parent_1_1_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_1_0", res, expected)

    # check e_2_parent_1_0
    expected = [e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_0", res, expected)

    # Check e_1_parent_2_1_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_2_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_2_1_0", res, expected)

    # check e_2_parent_2_1_0
    expected = [ e_1_parent_2_2_1_0 ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_2_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_2_1_0", res, expected)

    # Check e_1_parent_3_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_3_0", res, expected)

    # Check e_1_parent_1_3_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_3_0", res, expected)

    # Check e_1_parent_1_1_3_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_3_0", res, expected)

    # Check e_1_parent_1_1_1_3_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_1_3_0", res, expected)

    def fin():
        entries = [e_1_parent_0, e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0, e_2_parent_1_0, e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0, e_2_parent_0, e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0, e_3_parent_0, e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
        for entry in entries:
            topo.standalone.delete_s(entry)
        topo.standalone.delete_s(dn_config)
        topo.standalone.delete_s(dn_subtree)

    request.addfinalizer(fin)

def test_slapi_memberof_excludescope(topo, request):
    """
    Test that membership hierarchy (member) is computed with slapi_member
    Entries in the subtree excludeescope (e_2_parent_1_0) are ignored
    computation of the membership
    with following parameters
                 membership attribute: 'manager'
                 span over all backends: 'on'
                 skip nesting membership: 'off'
                 computation mode: recompute
                 Scope: DEFAULT_SUFFIX
                 ExcludeScope: ou=subtree,ou=People,dc=example,dc=com  <----
                 Maximum return entries: None

    :id: 6c7587e0-0bc4-4847-b403-773d7314aa31
    :setup: Standalone instance
    :steps:
        1. provision a set of entries in default backend
        2. configure test_slapi_memberof as described above
           so entries under e_2_parent_1_0 are ignored
        3. check computed membership vs expected result
    :expectedresults:
        1. Operation should  succeed
        2. Operation should  succeed
        3. Operation should  succeed
    e_1_parent_0
        e_1_parent_1_0
            e_1_parent_1_1_0
                e_1_parent_1_1_1_0
                e_2_parent_1_1_1_0
                e_3_parent_1_1_1_0
                e_4_parent_1_1_1_0
                e_5_parent_1_1_1_0
            e_2_parent_1_1_0
        e_2_parent_1_0 (subtree)                <----
            e_1_parent_2_1_0 (subtree)          <----
            e_2_parent_2_1_0 (subtree)          <----
                e_1_parent_2_2_1_0 (subtree)    <----
            e_3_parent_2_1_0 (subtree)          <----
            e_4_parent_2_1_0 (subtree)          <----
    e_2_parent_0
        e_1_parent_2_0
        e_2_parent_2_0
        e_3_parent_2_0
        e_4_parent_2_0
    e_3_parent_0
        e_1_parent_3_0
            e_1_parent_1_3_0
                e_1_parent_1_1_3_0
                    e_1_parent_1_1_1_3_0
    """

    subtree="subtree"
    dn_subtree = 'ou=%s,ou=People,%s' % (subtree, DEFAULT_SUFFIX)
    topo.standalone.add_s(Entry((dn_subtree, {'objectclass': 'top organizationalunit'.split(),
                                              'ou': subtree})))
    # First subtree
    e_1_parent_0 = add_entry(topo.standalone, uid="e_1_parent_0")

    e_1_parent_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_1_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_2_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_3_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_3_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_4_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_4_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_5_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_5_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])

    e_2_parent_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_2_parent_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_0", manager=[ensure_bytes(e_1_parent_0)], subtree=subtree)

    e_1_parent_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)], subtree=subtree)
    e_2_parent_2_1_0 = add_entry(topo.standalone, uid="e_2_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)], subtree=subtree)
    e_1_parent_2_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_2_1_0", manager=[ensure_bytes(e_2_parent_2_1_0)], subtree=subtree)
    e_3_parent_2_1_0 = add_entry(topo.standalone, uid="e_3_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)], subtree=subtree)
    e_4_parent_2_1_0 = add_entry(topo.standalone, uid="e_4_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)], subtree=subtree)

    # 2nd subtree
    e_2_parent_0 = add_entry(topo.standalone, uid="e_2_parent_0")

    e_1_parent_2_0 = add_entry(topo.standalone, uid="e_1_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_2_parent_2_0 = add_entry(topo.standalone, uid="e_2_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_3_parent_2_0 = add_entry(topo.standalone, uid="e_3_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_4_parent_2_0 = add_entry(topo.standalone, uid="e_4_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])

    # third subtree
    e_3_parent_0 = add_entry(topo.standalone, uid="e_3_parent_0")

    e_1_parent_3_0 = add_entry(topo.standalone, uid="e_1_parent_3_0", manager=[ensure_bytes(e_3_parent_0)])

    e_1_parent_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_3_0", manager=[ensure_bytes(e_1_parent_3_0)])

    e_1_parent_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_3_0)])

    e_1_parent_1_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_1_3_0)])

    dn_config = 'cn=test_slapi_memberof,cn=plugins,cn=config'
    topo.standalone.add_s(Entry((dn_config, {'objectclass': 'top nsSlapdPlugin extensibleObject'.split(),
                             'cn': 'test_slapi_memberof',
                             'nsslapd-pluginPath': 'libtest_slapi_memberof-plugin',
                             'nsslapd-pluginInitfunc': 'test_slapi_memberof_init',
                             'nsslapd-pluginType': 'extendedop',
                             'nsslapd-pluginEnabled': 'on',
                             'nsslapd-plugin-depends-on-type': 'database',
                             'nsslapd-pluginId': 'test_slapi_memberof-plugin',
                             'slapimemberOfMemberDN': 'uid=test_user_11,ou=People,dc=example,dc=com',
                             'slapimemberOfGroupAttr': 'manager',
                             'slapimemberOfAttr': 'memberof',
                             'slapimemberOfAllBackends': 'on',
                             'slapimemberOfSkipNested': 'off',
                             'slapimemberOfEntryScopeExcludeSubtree': dn_subtree,
                             'slapimemberOfEntryScope': DEFAULT_SUFFIX,
                             'slapimemberOfMaxGroup': '0',
                             'nsslapd-pluginVersion': '2.3.2.202302131418git0e190fc3d',
                             'nsslapd-pluginVendor': '389 Project',
                             'nsslapd-pluginDescription': 'test_slapi_memberof extended operation plugin'})))
    topo.standalone.restart()

    # Check the first subtree
    expected = [ e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_0, relation="manager")
    _check_res_vs_expected("first subtree", res, expected)

    # Check the second subtree
    expected = [e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_0, relation="manager")
    _check_res_vs_expected("second subtree", res, expected)

    # Check the third subtree
    expected = [e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_3_parent_0, relation="manager")
    _check_res_vs_expected("third subtree", res, expected)

    # check e_1_parent_1_0
    expected = [e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_0", res, expected)

    # check e_1_parent_1_1_0
    expected = [e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_0", res, expected)

    # check e_2_parent_1_1_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_1_0", res, expected)

    # check e_2_parent_1_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_0", res, expected)

    # Check e_1_parent_2_1_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_2_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_2_1_0", res, expected)

    # check e_2_parent_2_1_0
    expected = [ EMPTY_RESULT ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_2_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_2_1_0", res, expected)

    # Check e_1_parent_3_0
    expected = [ e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0 ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_3_0", res, expected)

    # Check e_1_parent_1_3_0
    expected = [ e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0 ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_3_0", res, expected)

    # Check e_1_parent_1_1_3_0
    expected = [ e_1_parent_1_1_1_3_0 ]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_3_0", res, expected)

    # Check e_1_parent_1_1_1_3_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_1_3_0", res, expected)

    def fin():
        entries = [e_1_parent_0, e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0, e_2_parent_1_0, e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0, e_2_parent_0, e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0, e_3_parent_0, e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
        for entry in entries:
            topo.standalone.delete_s(entry)
        topo.standalone.delete_s(dn_config)
        topo.standalone.delete_s(dn_subtree)

    request.addfinalizer(fin)

def test_slapi_memberof_skip_nested(topo, request):
    """
    When searching the management (manager) hierarchy it stops at the first level
    no recursion
    Test that management hierarchy is computed with slapi_member
    It is done stopping at the first level, so the direct subordinate
    with following parameters
                 membership attribute: 'manager'
                 span over all backends: 'on'
                 skip nesting membership: 'on'  <----
                 computation mode: recompute
                 Scope: DEFAULT_SUFFIX
                 ExcludeScope: ou=subtree,ou=People,dc=example,dc=com
                 Maximum return entries: None

    :id: c9b5617f-9058-40f5-bdd6-a560bc67b30d
    :setup: Standalone instance
    :steps:
        1. provision a set of entries in default backend
        2. configure test_slapi_memberof as described above
        3. check computed membership vs expected result
           only direct subordinate are returned
    :expectedresults:
        1. Operation should  succeed
        2. Operation should  succeed
        3. Operation should  succeed

    e_1_parent_0
        e_1_parent_1_0
            e_1_parent_1_1_0
                e_1_parent_1_1_1_0
                e_2_parent_1_1_1_0
                e_3_parent_1_1_1_0
                e_4_parent_1_1_1_0
                e_5_parent_1_1_1_0
            e_2_parent_1_1_0
        e_2_parent_1_0
            e_1_parent_2_1_0
            e_2_parent_2_1_0
                e_1_parent_2_2_1_0
            e_3_parent_2_1_0
            e_4_parent_2_1_0
    e_2_parent_0
        e_1_parent_2_0
        e_2_parent_2_0
        e_3_parent_2_0
        e_4_parent_2_0
    e_3_parent_0
        e_1_parent_3_0
            e_1_parent_1_3_0
                e_1_parent_1_1_3_0
                    e_1_parent_1_1_1_3_0
    """

    subtree="subtree"
    dn_subtree = 'ou=%s,ou=People,%s' % (subtree, DEFAULT_SUFFIX)
    topo.standalone.add_s(Entry((dn_subtree, {'objectclass': 'top organizationalunit'.split(),
                                              'ou': subtree})))
    # First subtree
    e_1_parent_0 = add_entry(topo.standalone, uid="e_1_parent_0")

    e_1_parent_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_1_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_2_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_3_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_3_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_4_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_4_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_5_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_5_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])

    e_2_parent_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_2_parent_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_2_parent_2_1_0 = add_entry(topo.standalone, uid="e_2_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_1_parent_2_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_2_1_0", manager=[ensure_bytes(e_2_parent_2_1_0)])
    e_3_parent_2_1_0 = add_entry(topo.standalone, uid="e_3_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_4_parent_2_1_0 = add_entry(topo.standalone, uid="e_4_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])

    # 2nd subtree
    e_2_parent_0 = add_entry(topo.standalone, uid="e_2_parent_0")

    e_1_parent_2_0 = add_entry(topo.standalone, uid="e_1_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_2_parent_2_0 = add_entry(topo.standalone, uid="e_2_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_3_parent_2_0 = add_entry(topo.standalone, uid="e_3_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_4_parent_2_0 = add_entry(topo.standalone, uid="e_4_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])

    # third subtree
    e_3_parent_0 = add_entry(topo.standalone, uid="e_3_parent_0")

    e_1_parent_3_0 = add_entry(topo.standalone, uid="e_1_parent_3_0", manager=[ensure_bytes(e_3_parent_0)])

    e_1_parent_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_3_0", manager=[ensure_bytes(e_1_parent_3_0)])

    e_1_parent_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_3_0)])

    e_1_parent_1_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_1_3_0)])

    dn_config = 'cn=test_slapi_memberof,cn=plugins,cn=config'
    topo.standalone.add_s(Entry((dn_config, {'objectclass': 'top nsSlapdPlugin extensibleObject'.split(),
                             'cn': 'test_slapi_memberof',
                             'nsslapd-pluginPath': 'libtest_slapi_memberof-plugin',
                             'nsslapd-pluginInitfunc': 'test_slapi_memberof_init',
                             'nsslapd-pluginType': 'extendedop',
                             'nsslapd-pluginEnabled': 'on',
                             'nsslapd-plugin-depends-on-type': 'database',
                             'nsslapd-pluginId': 'test_slapi_memberof-plugin',
                             'slapimemberOfMemberDN': 'uid=test_user_11,ou=People,dc=example,dc=com',
                             'slapimemberOfGroupAttr': 'manager',
                             'slapimemberOfAttr': 'memberof',
                             'slapimemberOfAllBackends': 'on',
                             'slapimemberOfSkipNested': 'on',
                             'slapimemberOfEntryScope': DEFAULT_SUFFIX,
                             'slapimemberOfMaxGroup': '0',
                             'nsslapd-pluginVersion': '2.3.2.202302131418git0e190fc3d',
                             'nsslapd-pluginVendor': '389 Project',
                             'nsslapd-pluginDescription': 'test_slapi_memberof extended operation plugin'})))
    topo.standalone.restart()
    # Check the first subtree
    expected = [ e_1_parent_1_0, e_2_parent_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_0, relation="manager")
    _check_res_vs_expected("first subtree", res, expected)

    # Check the second subtree
    expected = [e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_0, relation="manager")
    _check_res_vs_expected("second subtree", res, expected)

    # Check the third subtree
    expected = [e_1_parent_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_3_parent_0, relation="manager")
    _check_res_vs_expected("third subtree", res, expected)

    # check e_1_parent_1_0
    expected = [e_1_parent_1_1_0, e_2_parent_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_0", res, expected)

    # check e_1_parent_1_1_0
    expected = [e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_0", res, expected)

    # check e_2_parent_1_1_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_1_0", res, expected)

    # check e_2_parent_1_0
    expected = [e_1_parent_2_1_0, e_2_parent_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_0", res, expected)

    # check e_2_parent_2_1_0
    expected = [e_1_parent_2_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_2_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_2_1_0", res, expected)

    # Check e_1_parent_3_0
    expected = [e_1_parent_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_3_0", res, expected)

    # Check e_1_parent_1_3_0
    expected = [e_1_parent_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_3_0", res, expected)

    # Check e_1_parent_1_1_3_0
    expected = [e_1_parent_1_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_3_0", res, expected)

    # Check e_1_parent_1_1_1_3_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_1_3_0", res, expected)

    def fin():
        entries = [e_1_parent_0, e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0, e_2_parent_1_0, e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0, e_2_parent_0, e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0, e_3_parent_0, e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
        for entry in entries:
            topo.standalone.delete_s(entry)
        topo.standalone.delete_s(dn_config)
        topo.standalone.delete_s(dn_subtree)

    request.addfinalizer(fin)

def test_slapi_memberof_maxgroup(topo, request):
    """
    When searching the management (manager) hierarchy it stops when
    a maximum subordinates are retrieved
    Test that management hierarchy is computed with slapi_member
    with following parameters
                 membership attribute: 'manager'
                 span over all backends: 'on'
                 skip nesting membership: 'off'  <----
                 computation mode: recompute
                 Scope: DEFAULT_SUFFIX
                 ExcludeScope: ou=subtree,ou=People,dc=example,dc=com
                 Maximum return entries: 3      <--

    :id: 83a4c668-99d0-4f47-ac89-a7f7fc620340
    :setup: Standalone instance
    :steps:
        1. provision a set of entries in default backend
        2. configure test_slapi_memberof as described above
        3. check computed membership vs expected result
           only direct subordinate are returned
    :expectedresults:
        1. Operation should  succeed
        2. Operation should  succeed
        3. Operation should  succeed
    max groups

    e_1_parent_0
        e_1_parent_1_0
            e_1_parent_1_1_0
                e_1_parent_1_1_1_0
                e_2_parent_1_1_1_0
                e_3_parent_1_1_1_0
                e_4_parent_1_1_1_0
                e_5_parent_1_1_1_0
            e_2_parent_1_1_0
        e_2_parent_1_0
            e_1_parent_2_1_0
            e_2_parent_2_1_0
                e_1_parent_2_2_1_0
            e_3_parent_2_1_0
            e_4_parent_2_1_0
    e_2_parent_0
        e_1_parent_2_0
        e_2_parent_2_0
        e_3_parent_2_0
        e_4_parent_2_0
    e_3_parent_0
        e_1_parent_3_0
            e_1_parent_1_3_0
                e_1_parent_1_1_3_0
                    e_1_parent_1_1_1_3_0
    """
    user = UserAccounts(topo.standalone, DEFAULT_SUFFIX)

    # First subtree
    e_1_parent_0 = add_entry(topo.standalone, uid="e_1_parent_0")

    e_1_parent_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_1_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_2_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_3_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_3_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_4_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_4_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])
    e_5_parent_1_1_1_0 = add_entry(topo.standalone, uid="e_5_parent_1_1_1_0", manager=[ensure_bytes(e_1_parent_1_1_0)])

    e_2_parent_1_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_1_0", manager=[ensure_bytes(e_1_parent_1_0)])

    e_2_parent_1_0 = add_entry(topo.standalone, uid="e_2_parent_1_0", manager=[ensure_bytes(e_1_parent_0)])

    e_1_parent_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_2_parent_2_1_0 = add_entry(topo.standalone, uid="e_2_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_1_parent_2_2_1_0 = add_entry(topo.standalone, uid="e_1_parent_2_2_1_0", manager=[ensure_bytes(e_2_parent_2_1_0)])
    e_3_parent_2_1_0 = add_entry(topo.standalone, uid="e_3_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])
    e_4_parent_2_1_0 = add_entry(topo.standalone, uid="e_4_parent_2_1_0", manager=[ensure_bytes(e_2_parent_1_0)])

    # 2nd subtree
    e_2_parent_0 = add_entry(topo.standalone, uid="e_2_parent_0")

    e_1_parent_2_0 = add_entry(topo.standalone, uid="e_1_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_2_parent_2_0 = add_entry(topo.standalone, uid="e_2_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_3_parent_2_0 = add_entry(topo.standalone, uid="e_3_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])
    e_4_parent_2_0 = add_entry(topo.standalone, uid="e_4_parent_2_0", manager=[ensure_bytes(e_2_parent_0)])

    # third subtree
    e_3_parent_0 = add_entry(topo.standalone, uid="e_3_parent_0")

    e_1_parent_3_0 = add_entry(topo.standalone, uid="e_1_parent_3_0", manager=[ensure_bytes(e_3_parent_0)])

    e_1_parent_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_3_0", manager=[ensure_bytes(e_1_parent_3_0)])

    e_1_parent_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_3_0)])

    e_1_parent_1_1_1_3_0 = add_entry(topo.standalone, uid="e_1_parent_1_1_1_3_0", manager=[ensure_bytes(e_1_parent_1_1_3_0)])

    dn_config = 'cn=test_slapi_memberof,cn=plugins,cn=config'
    topo.standalone.add_s(Entry((dn_config, {'objectclass': 'top nsSlapdPlugin extensibleObject'.split(),
                             'cn': 'test_slapi_memberof',
                             'nsslapd-pluginPath': 'libtest_slapi_memberof-plugin',
                             'nsslapd-pluginInitfunc': 'test_slapi_memberof_init',
                             'nsslapd-pluginType': 'extendedop',
                             'nsslapd-pluginEnabled': 'on',
                             'nsslapd-plugin-depends-on-type': 'database',
                             'nsslapd-pluginId': 'test_slapi_memberof-plugin',
                             'slapimemberOfMemberDN': 'uid=test_user_11,ou=People,dc=example,dc=com',
                             'slapimemberOfGroupAttr': 'manager',
                             'slapimemberOfAttr': 'memberof',
                             'slapimemberOfAllBackends': 'on',
                             'slapimemberOfSkipNested': 'off',
                             'slapimemberOfEntryScope': DEFAULT_SUFFIX,
                             'slapimemberOfMaxGroup': '3',
                             'nsslapd-pluginVersion': '2.3.2.202302131418git0e190fc3d',
                             'nsslapd-pluginVendor': '389 Project',
                             'nsslapd-pluginDescription': 'test_slapi_memberof extended operation plugin'})))
    topo.standalone.restart()

    # Check the first subtree
    expected = [ e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_0, relation="manager")
    _check_res_vs_expected("first subtree", res, expected)

    # Check the second subtree
    expected = [e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_0, relation="manager")
    _check_res_vs_expected("second subtree", res, expected)

    # Check the third subtree
    expected = [e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_3_parent_0, relation="manager")
    _check_res_vs_expected("third subtree", res, expected)

    # check e_1_parent_1_0
    expected = [e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_0", res, expected)

    # check e_1_parent_1_1_0
    expected = [e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_0", res, expected)

    # check e_2_parent_1_1_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_1_0", res, expected)

    # check e_2_parent_1_0
    expected = [e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_1_0", res, expected)

    # check e_2_parent_2_1_0
    expected = [e_1_parent_2_2_1_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_2_parent_2_1_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_2_parent_2_1_0", res, expected)

    # Check e_1_parent_3_0
    expected = [e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_3_0", res, expected)

    # Check e_1_parent_1_3_0
    expected = [e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_3_0", res, expected)

    # Check e_1_parent_1_1_3_0
    expected = [e_1_parent_1_1_1_3_0]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_3_0", res, expected)

    # Check e_1_parent_1_1_1_3_0
    expected = [EMPTY_RESULT]
    res = _extop_test_slapi_member(server=topo.standalone, dn=e_1_parent_1_1_1_3_0, relation="manager")
    _check_res_vs_expected("organisation reporting to e_1_parent_1_1_1_3_0", res, expected)

    def fin():
        entries = [e_1_parent_0, e_1_parent_1_0, e_1_parent_1_1_0, e_1_parent_1_1_1_0, e_2_parent_1_1_1_0, e_3_parent_1_1_1_0, e_4_parent_1_1_1_0, e_5_parent_1_1_1_0, e_2_parent_1_1_0, e_2_parent_1_0, e_1_parent_2_1_0, e_2_parent_2_1_0, e_1_parent_2_2_1_0, e_3_parent_2_1_0, e_4_parent_2_1_0, e_2_parent_0, e_1_parent_2_0, e_2_parent_2_0, e_3_parent_2_0, e_4_parent_2_0, e_3_parent_0, e_1_parent_3_0, e_1_parent_1_3_0, e_1_parent_1_1_3_0, e_1_parent_1_1_1_3_0]
        for entry in entries:
            topo.standalone.delete_s(entry)
        topo.standalone.delete_s(dn_config)

    request.addfinalizer(fin)

if __name__ == "__main__":
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main("-s -v %s" % CURRENT_FILE)
