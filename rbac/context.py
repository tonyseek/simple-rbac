#!/usr/bin/env python
#-*- coding:utf-8 -*-

import functools


class PermissionChecker(object):
    """A decorator to check the permission."""

    def __init__(self, checker, callback):
        self.checker = checker
        self.callback = callback
        functools.update_wrapper(self, callback)

    def __call__(self, *args, **kwargs):
        self.checker()
        return self.callback(*args, **kwargs)


class IdentityContext(object):
    """A context of identity, providing the enviroment to control access."""

    def __init__(self, acl, roles_loader=None):
        self.acl = acl
        self.set_role_loader(roles_loader)

    def set_role_loader(self, role_loader):
        self.load_roles = role_loader

    def check_permission(self, operation, resource, **exception_kwargs):
        checker = functools.partial(self._docheck, operation=operation,
                                    resource=resource, **exception_kwargs)
        return functools.partial(PermissionChecker, checker=checker)

    def _docheck(self, operation, resource, **exception_kwargs):
        roles = self.load_roles()
        if not self.acl.is_any_allowed(roles, operation, resource):
            raise PermissionDenied(**exception_kwargs)


class PermissionDenied(Exception):
    """The exception for denied access request."""

    def __init__(self, message="", **kwargs):
        super(PermissionDenied, self).__init__(message)
        self.kwargs = kwargs
