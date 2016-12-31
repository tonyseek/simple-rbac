from __future__ import absolute_import

import pytest

import rbac.acl
import rbac.proxy


# -----------
# Mock Models
# -----------

class BaseModel(object):
    """The mock model base."""

    storage = {}

    def __init__(self):
        self.storage[self.__class__.__name__, str(self.id)] = self
        return self

    @classmethod
    def query(cls, id):
        return cls.storage[cls.__name__, str(id)]


class Role(BaseModel):
    """The mock role model."""

    def __init__(self, name):
        self.name = name
        super(Role, self).__init__()

    @property
    def id(self):
        return self.name


class Group(BaseModel):
    """The group model, a mock resource model."""

    def __init__(self, name):
        self.name = name
        super(Group, self).__init__()

    @property
    def id(self):
        return self.name


class Post(BaseModel):
    """The post model, a mock resource model."""

    def __init__(self, title, author):
        self.title = title
        self.author = author
        super(Post, self).__init__()

    @property
    def id(self):
        return self.title


@pytest.fixture
def proxy():
    acl = rbac.acl.Registry()

    # create a acl and give it a proxy
    proxy = rbac.proxy.RegistryProxy(
        acl, role_factory=rbac.proxy.model_role_factory,
        resource_factory=rbac.proxy.model_resource_factory)

    # create roles
    proxy.add_role(Role('staff'))
    proxy.add_role(Role('editor'), [
        Role.query('staff'),
    ])
    proxy.add_role(Role('manager'), [
        Role.query('staff'),
        Role.query('editor'),
    ])

    # create rules
    proxy.allow(Role.query('staff'), 'create', Post)
    proxy.allow(Role.query('editor'), 'edit', Post)
    proxy.deny(Role.query('manager'), 'edit', Post)
    proxy.allow(Role.query('staff'), 'join', Group)

    return proxy


def test_undefined_models(proxy):
    visitor = Role('visitor')
    manager = Role.query('manager')
    staff = Role.query('staff')
    public_post = Post('This is public', 'Tom')

    proxy.allow(visitor, 'edit', public_post)
    proxy.deny(manager, 'edit', public_post)

    assert proxy.is_allowed(visitor, 'edit', public_post)
    assert not proxy.is_allowed(visitor, 'move', public_post)
    assert not proxy.is_allowed(manager, 'edit', public_post)
    assert not proxy.is_allowed(staff, 'edit', public_post)


def test_rules(proxy):
    post = Post('Special Post', 'nobody')
    group = Group('Special Group')

    for role in [Role.query('staff'), Role.query('editor')]:
        assert proxy.is_allowed(role, 'create', Post)
        assert proxy.is_allowed(role, 'create', post)
        assert proxy.is_allowed(role, 'join', Group)
        assert proxy.is_allowed(role, 'join', group)

    manager = Role.query('manager')
    assert not proxy.is_allowed(manager, 'edit', Post)
    assert not proxy.is_allowed(manager, 'edit', post)
    assert proxy.is_allowed(manager, 'join', Group)
    assert proxy.is_allowed(manager, 'join', group)


def test_recreate(proxy):
    BaseModel.storage.clear()

    for role in ['staff', 'editor', 'manager']:
        r = Role(role)
    del r

    test_rules(proxy)


def test_owner_assertion(proxy):
    data = {'current_user': 'tom'}
    staff = Role.query('staff')

    def staff_is_owner_assertion(acl, role, operation, resource):
        return Post.query(resource.id).author == data['current_user']

    proxy.allow(staff, 'edit', Post, staff_is_owner_assertion)

    post = Post("Tony's Post", 'tony')
    assert not proxy.is_allowed(staff, 'edit', post)
    data['current_user'] = 'tony'
    assert proxy.is_allowed(staff, 'edit', post)


def test_is_any_allowed(proxy):
    proxy.add_role(Role('nobody'))

    no_allowed = ['staff', 'nobody']
    no_allowed_one = ['staff']

    one_allowed = ['staff', 'editor', 'nobody']
    one_allowed_only = ['editor']

    one_denied = ['staff', 'nobody', 'manager']
    one_denied_with_allowed = ['staff', 'editor', 'manager']

    def test_result(roles):
        return proxy.is_any_allowed(
            (Role.query(r) for r in roles), 'edit', Post)

    for roles in (no_allowed, no_allowed_one):
        assert not test_result(roles)

    for roles in (one_allowed, one_allowed_only):
        assert test_result(roles)

    for roles in (one_denied, one_denied_with_allowed):
        assert not test_result(roles)
