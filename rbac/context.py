#!/usr/bin/env python
#-*- coding:utf-8 -*-

import functools


__all__ = ["IdentityContext", "PermissionDenied"]


class PermissionContext(object):
    """A context of decorator to check the permission."""

    def __init__(self, checker):
        self.check = checker
        self.in_context = False

    def __call__(self, wrapped):
        def wrapper(*args, **kwargs):
            with self:
                return wrapped(*args, **kwargs)
        return functools.update_wrapper(wrapper, wrapped)

    def __enter__(self):
        self.in_context = True
        self.check()
        return self

    def __exit__(self, exception_type, exception, traceback):
        self.in_context = False

    def __nonzero__(self):
        try:
            self.check()
        except PermissionDenied:
            return False
        else:
            return True


class IdentityContext(object):
    """A context of identity, providing the enviroment to control access."""

    def __init__(self, acl, roles_loader=None):
        self.acl = acl
        self.set_roles_loader(roles_loader)

    def set_roles_loader(self, role_loader):
        """Set a callable object (such as a function) which could return a
        iteration to provide all roles of current context user.

        Example:
        >>> @context.set_roles_loader
        ... def load_roles():
        ...     user = request.context.current_user
        ...     for role in user.roles:
        ...         yield role
        """
        self.load_roles = role_loader

    def check_permission(self, operation, resource, **exception_kwargs):
        """A decorator to check the permission.

        The keyword arguments would be stored into the attribute `kwargs` of
        the exception `PermissionDenied`.
        """
        checker = functools.partial(self._docheck, operation=operation,
                                    resource=resource, **exception_kwargs)
        return PermissionContext(checker)

    def _docheck(self, operation, resource, **exception_kwargs):
        roles = self.load_roles()
        if not self.acl.is_any_allowed(roles, operation, resource):
            exception = exception_kwargs.pop("exception", PermissionDenied)
            raise exception(**exception_kwargs)
        return True


class PermissionDenied(Exception):
    """The exception for denied access request."""

    def __init__(self, message="", **kwargs):
        super(PermissionDenied, self).__init__(message)
        self.kwargs = kwargs
        self.kwargs['message'] = message
