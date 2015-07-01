#!/usr/bin/env python
#-*- coding:utf-8 -*-

import itertools


__all__ = ["Registry"]


class Registry(object):
    """The registry of access control list."""

    def __init__(self):
        self._roles = {}
        self._resources = {}
        self._allowed = {}
        self._denied = {}
        self._denial_only_roles = set()  # to allow additional short circuiting, track roles that only ever deny access
        self._children = {}

    def add_role(self, role, parents=[]):
        """Add a role or append parents roles to a special role.

        All added roles should be hashable.
        (http://docs.python.org/glossary.html#term-hashable)
        """
        self._roles.setdefault(role, set())
        self._roles[role].update(parents)
        for p in parents:
            self._children.setdefault(p, set())
            self._children[p].add(role)

        # all roles start as deny-only (unless one of its parents isn't deny-only)
        if not parents or self._roles_are_deny_only(parents):
            self._denial_only_roles.add(role)

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
        self._allowed[role, operation, resource] = assertion

        # since we just allowed a permission, role and any children aren't denied-only
        for r in itertools.chain([role], get_family(self._children, role)):
            self._denial_only_roles.discard(r)

    def deny(self, role, operation, resource, assertion=None):
        """Add a denied rule.

        The added rule will deny the role and its all children roles to
        operate the resource.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources
        self._denied[role, operation, resource] = assertion

    def is_allowed(self, role, operation, resource, check_allowed=True, **assertion_kwargs):
        """Check the permission.

        If the access is denied, this method will return False; if the access
        is allowed, this method will return True; if there is not any rule
        for the access, this method will return None.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources

        roles = set(get_family(self._roles, role))
        operations = {None, operation}
        resources = set(get_family(self._resources, resource))

        is_allowed = None
        default_assertion = lambda *args, **kwargs: True

        for permission in itertools.product(roles, operations, resources):
            if permission in self._denied:
                assertion = self._denied[permission] or default_assertion
                if assertion(self, role, operation, resource, **assertion_kwargs):
                    return False  # denied by rule immediately

            if check_allowed and permission in self._allowed:
                assertion = self._allowed[permission] or default_assertion
                if assertion(self, role, operation, resource, **assertion_kwargs):
                    is_allowed = True  # allowed by rule

        return is_allowed

    def is_any_allowed(self, roles, operation, resource, **assertion_kwargs):
        """Check the permission with many roles."""
        is_allowed = None  # no matching rules
        for i, role in enumerate(roles):
            # if access not yet allowed and all remaining roles could only deny access, short-circuit and return False
            if not is_allowed and self._roles_are_deny_only(roles[i:]):
                return False

            check_allowed = not is_allowed  # if another role gave access, don't bother checking if this one is allowed
            is_current_allowed = self.is_allowed(
                role, operation, resource, check_allowed=check_allowed, **assertion_kwargs)
            if is_current_allowed is False:
                return False  # denied by rule
            elif is_current_allowed is True:
                is_allowed = True
        return is_allowed

    def _roles_are_deny_only(self, roles):
        return all(r in self._denial_only_roles for r in roles)


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
