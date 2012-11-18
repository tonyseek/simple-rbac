#!/usr/bin/env python
#-*- coding:utf-8 -*-

import itertools
import functools


__all__ = ["Registry"]


class Registry(object):
    """The registry of access control list."""

    def __init__(self):
        self._roles = {}
        self._resources = {}
        self._allowed = {}
        self._denied = {}

    def add_role(self, role, parents=[]):
        """Add a role or append parents roles to a special role.

        All added roles should be hashable.
        (http://docs.python.org/glossary.html#term-hashable)
        """
        self._roles.setdefault(role, set())
        self._roles[role].update(parents)

    def add_resource(self, resource, parents=[]):
        """Add a resource or append parents resources to a special resource.

        All added resources should be hashable.
        (http://docs.python.org/glossary.html#term-hashable)
        """
        self._resources.setdefault(resource, set())
        self._resources[resource].update(parents)

    def allow(self, role, operation, resource, assertion=None):
        """Add a allowed rule.

        The added rule will allow the role and its all children roles to
        operate the resource.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources
        rule_key = (role, operation, resource)
        self._allowed[rule_key] = assertion
        #: return a decorator to reset assertion
        return functools.partial(self._allowed.__setitem__, rule_key)

    def deny(self, role, operation, resource, assertion=None):
        """Add a denied rule.

        The added rule will deny the role and its all children roles to
        operate the resource.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources
        rule_key = (role, operation, resource)
        self._denied[rule_key] = assertion
        #: return a decorator to reset assertion
        return functools.partial(self._denied.__setitem__, rule_key)

    def is_allowed(self, role, operation, resource):
        """Check the permission.

        If the access is denied, this method will return False; if the access
        is allowed, this method will return True; if there is not any rule
        for the access, this method will return None.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources

        roles = set(get_family(self._roles, role))
        operations = set([None, operation])
        resources = set(get_family(self._resources, resource))

        is_allowed = None
        default_assertion = lambda *args: True

        for permission in itertools.product(roles, operations, resources):
            if permission in self._denied:
                assertion = self._denied[permission] or default_assertion
                if assertion(self, role, operation, resource):
                    return False  # denied by rule immediately

            if permission in self._allowed:
                assertion = self._allowed[permission] or default_assertion
                if assertion(self, role, operation, resource):
                    is_allowed = True  # allowed by rule

        return is_allowed

    def is_any_allowed(self, roles, operation, resource):
        """Check the permission with many roles."""
        is_allowed = None  # there is not matching rules
        for role in frozenset(roles):
            is_current_allowed = self.is_allowed(role, operation, resource)
            if is_current_allowed is False:
                return False  # denied by rule
            elif is_current_allowed is True:
                is_allowed = True
        return is_allowed


def get_family(parents, current):
    """Iterate current object and its all parents recursively."""
    #: itself
    yield current
    #: if parents is dynamic, call the factory now
    if callable(parents):
        parents = parents()
    #: iterate parents recursively
    for parent in get_parents(parents, current):
        yield parent
    #: None means any
    yield None


def get_parents(all_parents, current):
    """Iterate current object's all parents."""
    for parent in all_parents.get(current, []):
        yield parent
        for grandparent in get_parents(all_parents, parent):
            yield grandparent
