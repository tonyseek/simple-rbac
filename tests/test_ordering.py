#!/usr/bin/env python
#-*- coding:utf-8 -*-

import unittest

import rbac.acl
import rbac.context


class _FunctionProxy(object):
        def __init__(self, fn, evaluated_roles, role_idx=0):
            self.fn = fn
            self.role_idx = role_idx
            self.evaluated_roles = evaluated_roles

        def __call__(self, *args, **kwargs):
            role = args[self.role_idx]
            self.evaluated_roles.append(role)
            return self.fn.__call__(*args, **kwargs)


class OrderingTestCase(unittest.TestCase):

    def setUp(self):
        self.acl = rbac.acl.Registry()
        self.context = rbac.context.IdentityContext(self.acl)
        self.evaluated_roles = []

    def test_role_evaluation_order_preserved(self):
        # decorate acl.is_allowed so we can track role evaluation order
        setattr(self.acl, 'is_allowed', _FunctionProxy(self.acl.is_allowed, self.evaluated_roles))

        # add roles as a list in the expected order (1 through 10)
        self.acl.add_resource('my_resource')
        roles = [str(i) for i in xrange(10)]
        for i, role in enumerate(roles):
            self.acl.add_role(role)
        self.context.set_roles_loader(lambda: roles)
        self.acl.allow(roles[9], 'view', 'my_resource')  # allow only the final role to avoid short-circuiting
        self.context.has_permission('view', 'my_resource')

        # check that the roles were evaluated in order
        self.assertEqual(roles, self.evaluated_roles)

    def test_short_circuit_skip_deny(self):
        """ If no remaining role could grant access, don't bother checking """
        # track which roles are evaluated
        setattr(self.acl, 'is_allowed', _FunctionProxy(self.acl.is_allowed, self.evaluated_roles))

        self.acl.add_resource('the dinosaurs')
        roles = ['tourist', 'scientist', 'intern']
        for role in roles:
            self.acl.add_role(role)
        self.context.set_roles_loader(lambda: roles)
        # explicitly deny one role, and simply don't allow any permissions to the others
        self.acl.deny('intern', 'feed', 'the dinosaurs')
        self.context.has_permission('feed', 'the dinosaurs')

        # no roles checked, since all are deny-only
        self.assertEqual([], self.evaluated_roles)

        self.acl.allow('scientist', 'study', 'the dinosaurs')
        self.context.has_permission('feed', 'the dinosaurs')

        # since scientist is no longer deny-only, only the intern check will be skipped
        self.assertEqual(['tourist', 'scientist'], self.evaluated_roles)

    def test_short_circuit_skip_allow(self):
        """ once one role is allowed, shouldn't check whether other roles are allowed """
        # track which roles have their assertion function evaluated
        assertion = _FunctionProxy(lambda *args, **kwargs: args[1] == '3', self.evaluated_roles, role_idx=1)

        self.acl.add_resource('my_resource')
        roles = [str(i) for i in xrange(10)]
        for i, role in enumerate(roles):
            self.acl.add_role(role)
            self.acl.allow(role, 'view', 'my_resource', assertion=assertion)
        self.context.set_roles_loader(lambda: roles)
        self.context.has_permission('view', 'my_resource')

        # since role '3' was allowed, 'allowed' isn't checked on any subsequent role
        self.assertEqual(roles[0:4], self.evaluated_roles)
