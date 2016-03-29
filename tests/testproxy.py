#!/usr/bin/env python
#-*- coding:utf-8 -*-

import unittest

import rbac.acl
import rbac.proxy

import testacl


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


# ----------
# Test Cases
# ----------

class ProxyTestCase(unittest.TestCase):

    def setUp(self):
        # create a acl and give it a proxy
        self.acl = rbac.acl.Registry()
        self.proxy = rbac.proxy.RegistryProxy(self.acl,
                role_factory=rbac.proxy.model_role_factory,
                resource_factory=rbac.proxy.model_resource_factory)

        # create roles
        self.proxy.add_role(Role("staff"))
        self.proxy.add_role(Role("editor"), [Role.query("staff")])
        self.proxy.add_role(Role("manager"),
                [Role.query("staff"), Role.query("editor")])

        # create rules
        self.proxy.allow(Role.query("staff"), "create", Post)
        self.proxy.allow(Role.query("editor"), "edit", Post)
        self.proxy.deny(Role.query("manager"), "edit", Post)
        self.proxy.allow(Role.query("staff"), "join", Group)

    def test_undefined_models(self):
        visitor = Role("visitor")
        manager = Role.query("manager")
        staff = Role.query("staff")
        public_post = Post("This is public", "Tom")

        self.proxy.allow(visitor, "edit", public_post)
        self.proxy.deny(manager, "edit", public_post)

        self.assertTrue(self.proxy.is_allowed(visitor, "edit", public_post))
        self.assertFalse(self.proxy.is_allowed(visitor, "move", public_post))
        self.assertFalse(self.proxy.is_allowed(manager, "edit", public_post))
        self.assertFalse(self.proxy.is_allowed(staff, "edit", public_post))

    def test_rules(self):
        post = Post("Special Post", "nobody")
        group = Group("Special Group")

        for role in [Role.query("staff"), Role.query("editor")]:
            self.assertTrue(self.proxy.is_allowed(role, "create", Post))
            self.assertTrue(self.proxy.is_allowed(role, "create", post))
            self.assertTrue(self.proxy.is_allowed(role, "join", Group))
            self.assertTrue(self.proxy.is_allowed(role, "join", group))

        manager = Role.query("manager")
        self.assertFalse(self.proxy.is_allowed(manager, "edit", Post))
        self.assertFalse(self.proxy.is_allowed(manager, "edit", post))
        self.assertTrue(self.proxy.is_allowed(manager, "join", Group))
        self.assertTrue(self.proxy.is_allowed(manager, "join", group))

    def test_recreate(self):
        BaseModel.storage.clear()

        for role in ["staff", "editor", "manager"]:
            r = Role(role)
        del r

        self.test_rules()

    def test_owner_assertion(self):
        data = {'current_user': "tom"}
        staff = Role.query("staff")

        def staff_is_owner_assertion(acl, role, operation, resource):
            return Post.query(resource.id).author == data['current_user']

        self.proxy.allow(staff, "edit", Post, staff_is_owner_assertion)

        post = Post("Tony's Post", "tony")
        self.assertFalse(self.proxy.is_allowed(staff, "edit", post))
        data['current_user'] = "tony"
        self.assertTrue(self.proxy.is_allowed(staff, "edit", post))

    def test_is_any_allowed(self):
        self.proxy.add_role(Role("nobody"))

        no_allowed = ["staff", "nobody"]
        no_allowed_one = ["staff"]

        one_allowed = ["staff", "editor", "nobody"]
        one_allowed_only = ["editor"]

        one_denied = ["staff", "nobody", "manager"]
        one_denied_with_allowed = ["staff", "editor", "manager"]

        test_result = lambda roles: self.proxy.is_any_allowed(
            (Role.query(r) for r in roles), "edit", Post)

        for roles in (no_allowed, no_allowed_one):
            self.assertFalse(test_result(roles))

        for roles in (one_allowed, one_allowed_only):
            self.assertTrue(test_result(roles))

        for roles in (one_denied, one_denied_with_allowed):
            self.assertFalse(test_result(roles))


class CompatibilityTestCase(testacl.AclTestCase):
    """Assert the proxy is compatibility with plain acl registry."""

    registry_acl = lambda: rbac.proxy.RegistryProxy(rbac.acl.Registry())
