#!/usr/bin/env python
#-*- coding:utf-8 -*-

import operator
import functools


#: a symbol means "any resource", "any role" or "assertion always true"
ANY = None


class Role(object):
    """The standard role model."""

    def __init__(self, name, parents=None):
        self.name = name
        self.parents = parents or set()
        self._allowed = {}
        self._denied = {}

    def add_child(self, child_role):
        child_role.parents.add(self)

    def allow(self, operation, resource=ANY, assertion=ANY):
        return self._add_rule(self._allowed, operation, resource, assertion)

    def deny(self, operation, resource=ANY, assertion=ANY):
        return self._add_rule(self._denied, operation, resource, assertion)

    def _add_rule(self, rule_table, operation, resource, assertion):
        permission = (operation, resource)
        rule_table[permission] = assertion
        return functools.partial(operator.setitem, rule_table, permission)


class GenericResource(object):
    """The resource partial model.

    You could mix in this class to your resource but it is not required. The
    access controller would accept all objects which has interface included
    readable attribute named "resource_id" and "resource_type".
    """

    @property
    def resource_id(self):
        return hash(self)

    @property
    def resource_type(self):
        return self.__class__.__name__
