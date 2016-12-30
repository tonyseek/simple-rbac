#!/usr/bin/env python
# -*- coding:utf-8 -*-

import functools
import collections


__all__ = ["dummy_factory", "model_role_factory", "model_resource_factory",
           "RegistryProxy"]

# identity tuple
identity = collections.namedtuple("identity", ["type", "cls", "id"])
role_identity = functools.partial(identity, "role-model")
resource_identity = functools.partial(identity, "resource-model")


def GetFullName(m):
    return "%s.%s" % (m.__module__, m.__name__)


def DummyFactory(acl, obj):
    return obj


# inline functions
getfullname = GetFullName
dummy_factory = DummyFactory


def _model_identity_factory(obj, identity_maker, identity_adder):
    if not hasattr(obj, "id"):
        return obj

    if isinstance(obj, type):
        # make a identity tuple for the "class"
        identity = identity_maker(getfullname(obj), None)
        # register into access control list
        identity_adder(identity)
    else:
        # make a identity tuple for the "instance" and the "class"
        class_fullname = getfullname(obj.__class__)
        identity = identity_maker(class_fullname, obj.id)
        identity_type = identity_maker(class_fullname, None)
        # register into access control list
        identity_adder(identity, parents=[identity_type])

    return identity


def model_role_factory(acl, obj):
    """A factory to create a identity tuple from a model class or instance."""
    return _model_identity_factory(obj, role_identity, acl.add_role)


def model_resource_factory(acl, obj):
    """A factory to create a identity tuple from a model class or instance."""
    return _model_identity_factory(obj, resource_identity, acl.add_resource)


class RegistryProxy(object):
    """A proxy of the access control list.

    This proxy could use two factory function to create the role identity
    object and the resource identity object automatic.

    A example for the factory function:
    >>> def role_factory(acl, input_role):
    >>>     role = ("my-role", str(input_role))
    >>>     acl.add_role(role)
    >>>     return role
    """

    def __init__(self, acl, role_factory=dummy_factory,
                 resource_factory=model_resource_factory):
        self.acl = acl
        self.make_role = functools.partial(role_factory, self.acl)
        self.make_resource = functools.partial(resource_factory, self.acl)

    def add_role(self, role, parents=[]):
        role = self.make_role(role)
        parents = [self.make_role(parent) for parent in parents]
        return self.acl.add_role(role, parents)

    def add_resource(self, resource, parents=[]):
        resource = self.make_resource(resource)
        parents = [self.make_resource(parent) for parent in parents]
        return self.acl.add_resource(resource, parents)

    def allow(self, role, operation, resource, assertion=None):
        role = self.make_role(role)
        resource = self.make_resource(resource)
        return self.acl.allow(role, operation, resource, assertion)

    def deny(self, role, operation, resource, assertion=None):
        role = self.make_role(role)
        resource = self.make_resource(resource)
        return self.acl.deny(role, operation, resource, assertion)

    def is_allowed(self, role, operation, resource, **assertion_kwargs):
        role = self.make_role(role)
        resource = self.make_resource(resource)
        return self.acl.is_allowed(role, operation,
                                   resource, **assertion_kwargs)

    def is_any_allowed(self, roles, operation, resource, **assertion_kwargs):
        roles = [self.make_role(role) for role in roles]
        resource = self.make_resource(resource)
        return self.acl.is_any_allowed(roles, operation,
                                       resource, **assertion_kwargs)

    def __getattr__(self, attr):
        return getattr(self.acl, attr)
