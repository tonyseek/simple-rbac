from __future__ import absolute_import

import functools


__all__ = ["IdentityContext", "PermissionDenied"]


class PermissionContext(object):
    """A context of decorator to check the permission."""

    def __init__(self, checker, exception=None, **exception_kwargs):
        self._check = checker
        self.in_context = False
        self.exception = exception or PermissionDenied
        self.exception_kwargs = exception_kwargs

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

    def __bool__(self):
        return bool(self._check())

    def __nonzero__(self):
        return self.__bool__()

    def check(self):
        if not self._check():
            raise self.exception(**self.exception_kwargs)
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

    def check_permission(self, operation, resource,
                         assertion_kwargs=None, **exception_kwargs):
        """A context to check the permission.

        The keyword arguments would be stored into the attribute `kwargs` of
        the exception `PermissionDenied`.

        If the key named `exception` is existed in the `kwargs`, it will be
        used instead of the `PermissionDenied`.

        The return value of this method could be use as a decorator, a with
        context enviroment or a boolean-like value.
        """
        exception = exception_kwargs.pop("exception", PermissionDenied)
        checker = functools.partial(self._docheck,
                                    operation=operation, resource=resource,
                                    **assertion_kwargs or {})
        return PermissionContext(checker, exception, **exception_kwargs)

    def has_permission(self, *args, **kwargs):
        return bool(self.check_permission(*args, **kwargs))

    def has_roles(self, role_groups):
        had_roles = frozenset(self.load_roles())
        return any(all(role in had_roles for role in role_group)
                   for role_group in role_groups)

    def _docheck(self, operation, resource, **assertion_kwargs):
        had_roles = self.load_roles()
        role_list = list(had_roles)
        assert len(role_list) == len(set(role_list))  # duplicate role check
        return self.acl.is_any_allowed(role_list, operation, resource,
                                       **assertion_kwargs)


class PermissionDenied(Exception):
    """The exception for denied access request."""

    def __init__(self, message="", **kwargs):
        super(PermissionDenied, self).__init__(message)
        self.kwargs = kwargs
        self.kwargs['message'] = message
