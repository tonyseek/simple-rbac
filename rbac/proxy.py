#!/usr/bin/env python
#-*- coding:utf-8 -*-

import functools
import collections


# identity tuple
identity = collections.namedtuple("identity", ["type", "cls", "id"])
role_identity = functools.partial(identity, "role-model")
resource_identity = functools.partial(identity, "resource-model")

# inline functions
getfullname = lambda m: "%s.%s" % (m.__module__, m.__name__)
dummy_factory = lambda acl, obj: obj


def model_role_factory(acl, obj):
    """A factory to create a identity tuple from a model class or instance."""
    if isinstance(obj, type):
        # make a identity tuple for the "class"
        identity = role_identity(getfullname(obj), None)
        # register into access control list
        acl.add_role(identity)
    else:
        # make a identity tuple for the "instance" and the "class"
        class_fullname = getfullname(obj.__class__)
        identity = role_identity(class_fullname, obj.id)
        identity_type = role_identity(class_fullname, None)
        # register into access control list
        acl.add_role(identity, parents=[identity_type])
    return identity


def model_resource_factory(acl, obj):
    """A factory to create a identity tuple from a model class or instance."""
    # yes, you're right, this is a copy-and-paste programming.
    if isinstance(obj, type):
        identity = resource_identity(getfullname(obj), None)
        acl.add_resource(identity)
    else:
        class_fullname = getfullname(obj.__class__)
        identity = resource_identity(class_fullname, obj.id)
        identity_type = resource_identity(class_fullname, None)
        acl.add_resource(identity, parents=[identity_type])
    return identity


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

    def is_allowed(self, role, operation, resource):
        role = self.make_role(role)
        resource = self.make_resource(resource)
        return self.acl.is_allowed(role, operation, resource)

    def __getattr__(self, attr):
        return getattr(self.acl, attr)
