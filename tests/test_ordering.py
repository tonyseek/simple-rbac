from __future__ import absolute_import

import pytest

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


@pytest.fixture
def acl():
    return rbac.acl.Registry()


@pytest.fixture
def context(acl):
    return rbac.context.IdentityContext(acl)


@pytest.fixture
def evaluated_roles():
    return []


def test_role_evaluation_order_preserved(acl, context, evaluated_roles):
    # decorate acl.is_allowed so we can track role evaluation order
    setattr(acl, 'is_allowed', _FunctionProxy(acl.is_allowed, evaluated_roles))

    # add roles as a list in the expected order (1 through 10)
    acl.add_resource('my_resource')
    roles = [str(i) for i in xrange(10)]
    for i, role in enumerate(roles):
        acl.add_role(role)
    context.set_roles_loader(lambda: roles)

    # allow only the final role to avoid short-circuiting
    acl.allow(roles[9], 'view', 'my_resource')
    context.has_permission('view', 'my_resource')

    # check that the roles were evaluated in order
    assert evaluated_roles == roles


def test_short_circuit_skip_deny(acl, context, evaluated_roles):
    """ If no remaining role could grant access, don't bother checking """
    # track which roles are evaluated
    setattr(acl, 'is_allowed', _FunctionProxy(acl.is_allowed, evaluated_roles))

    acl.add_resource('the dinosaurs')
    roles = ['tourist', 'scientist', 'intern']
    for role in roles:
        acl.add_role(role)
    context.set_roles_loader(lambda: roles)
    # explicitly deny one role and don't allow any permissions to others
    acl.deny('intern', 'feed', 'the dinosaurs')
    context.has_permission('feed', 'the dinosaurs')

    # no roles checked, since all are deny-only
    assert evaluated_roles == []

    acl.allow('scientist', 'study', 'the dinosaurs')
    context.has_permission('feed', 'the dinosaurs')

    # since scientist is no longer deny-only,
    # only the intern check will be skipped
    assert evaluated_roles == ['tourist', 'scientist']


def test_short_circuit_skip_allow(acl, context, evaluated_roles):
    """Once one role is passed, shouldn't other roles should not be checked."""
    # track which roles have their assertion function evaluated
    assertion = _FunctionProxy(lambda *args, **kwargs: args[1] == '3',
                               evaluated_roles, role_idx=1)

    acl.add_resource('my_resource')
    roles = [str(i) for i in xrange(10)]
    for i, role in enumerate(roles):
        acl.add_role(role)
        acl.allow(role, 'view', 'my_resource', assertion=assertion)
    context.set_roles_loader(lambda: roles)
    context.has_permission('view', 'my_resource')

    # since role '3' was allowed, 'allowed' isn't checked on any role
    assert evaluated_roles == roles[0:4]
