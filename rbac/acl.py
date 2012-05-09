#!/usr/bin/env python
#-*- coding:utf-8 -*-

import itertools


class Registry(object):
    """The registry of access control list."""

    def __init__(self):
        self._roles = {}
        self._resources = {}
        self._allowed = {}
        self._denied = {}

    def add_role(self, role, parents=[]):
        """Add a role.

        All added roles should be hashable.
        (http://docs.python.org/glossary.html#term-hashable)
        """
        self._roles[role] = frozenset(parents)

    def add_resource(self, resource, parents=[]):
        """Add a resource.

        All added resources should be hashable.
        (http://docs.python.org/glossary.html#term-hashable)
        """
        self._resources[resource] = frozenset(parents)

    def allow(self, role, operation, resource, assertion=None):
        """Add a allowed rule.

        The added rule will allow the role and its all children roles to
        operate the resource.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources
        self._allowed[role, operation, resource] = assertion

    def deny(self, role, operation, resource, assertion=None):
        """Add a denied rule.

        The added rule will deny the role and its all children roles to
        operate the resource.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources
        self._denied[role, operation, resource] = assertion

    def is_allowed(self, role, operation, resource):
        """Check the permission."""
        assert not role or role in self._roles
        assert not resource or resource in self._resources

        roles = set(get_family(self._roles, role))
        operations = set([None, operation])
        resources = set(get_family(self._resources, resource))

        is_allowed = False
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


def get_family(all_parents, current):
    """Iterate current object and its all parents recursively."""
    yield current
    for parent in get_parents(all_parents, current):
        yield parent
    yield None


def get_parents(all_parents, current):
    """Iterate current object's all parents."""
    for parent in all_parents.get(current, []):
        yield parent
        for grandparent in get_parents(all_parents, parent):
            yield grandparent
