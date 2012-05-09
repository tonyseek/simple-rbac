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
        self._allowed[role, operation, resource] = assertion

    def deny(self, role, operation, resource, assertion=None):
        """Add a denied rule.

        The added rule will deny the role and its all children roles to
        operate the resource.
        """
        self._denied[role, operation, resource] = assertion

    def is_allowed(self, role, operation, resource):
        roles = set(get_family(self._roles, role))
        operations = set([None, operation])
        resources = set(get_family(self._resources, resource))

        for permission in itertools.product(roles, operations, resources):
            if permission in self._denied:
                assertion = self._denied[permission]
                if not assertion:
                    return False  # denied by rule
                if assertion(self, role, operation, resource):
                    return False  # denied by rule and assertion

            if permission in self._allowed:
                assertion = self._allowed[permission]
                if not assertion:
                    return True  # allowed by rule
                if assertion(self, role, operation, resource):
                    return True  # allowed by rule and assertion

        return False  # default to deny


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
