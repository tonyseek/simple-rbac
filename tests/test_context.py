from __future__ import absolute_import

import pytest

import rbac.acl
import rbac.context


@pytest.fixture
def acl():
    # create context
    acl = rbac.acl.Registry()
    # self.denied_error = rbac.context.PermissionDenied

    # register roles and resources
    acl.add_role('staff')
    acl.add_role('editor', parents=['staff'])
    acl.add_role('badguy', parents=['staff'])
    acl.add_resource('article')

    # add rules
    acl.allow('staff', 'view', 'article')
    acl.allow('editor', 'edit', 'article')
    acl.deny('badguy', None, 'article')

    return acl


@pytest.fixture
def context(acl):
    return rbac.context.IdentityContext(acl)


@pytest.fixture
def role_provider(acl, context):
    class singleton(object):
        def to_be_staff(self):
            @context.set_roles_loader
            def load_roles():
                yield 'staff'

            yield 0

        def to_be_editor(self):
            @context.set_roles_loader
            def load_roles_0():
                yield 'editor'

            yield 0

            @context.set_roles_loader
            def load_roles_1():
                yield 'staff'
                yield 'editor'

            yield 1

        def to_be_badguy(self):
            @context.set_roles_loader
            def load_roles_0():
                yield 'badguy'

            yield 0

            @context.set_roles_loader
            def load_roles_1():
                yield 'staff'
                yield 'badguy'

            yield 1

            @context.set_roles_loader
            def load_roles_2():
                yield 'editor'
                yield 'badguy'

            yield 2

            @context.set_roles_loader
            def load_roles_3():
                yield 'staff'
                yield 'editor'
                yield 'badguy'

            yield 3

        def assert_call(self, view_article, edit_article):
            for _ in self.to_be_staff():
                assert view_article()
                with pytest.raises(rbac.context.PermissionDenied):
                    edit_article()

            for _ in self.to_be_editor():
                assert view_article()
                assert edit_article()

            for _ in self.to_be_badguy():
                with pytest.raises(rbac.context.PermissionDenied):
                    view_article()
                with pytest.raises(rbac.context.PermissionDenied):
                    edit_article()

    return singleton()


def test_decorator(acl, context, role_provider):
    @context.check_permission('view', 'article')
    def view_article():
        return True

    @context.check_permission('edit', 'article')
    def edit_article():
        return True

    role_provider.assert_call(view_article, edit_article)


def test_with_statement(acl, context, role_provider):
    def view_article():
        with context.check_permission('view', 'article'):
            return True

    def edit_article():
        with context.check_permission('edit', 'article'):
            return True

    role_provider.assert_call(view_article, edit_article)


def test_check_function(acl, context, role_provider):
    check_view = context.check_permission('view', 'article').check
    check_edit = context.check_permission('edit', 'article').check
    role_provider.assert_call(check_view, check_edit)


def test_nonzero(acl, context, role_provider):
    check_view = context.check_permission('view', 'article')
    check_edit = context.check_permission('edit', 'article')

    for _ in role_provider.to_be_staff():
        assert bool(check_view)
        assert not bool(check_edit)

    for _ in role_provider.to_be_editor():
        assert bool(check_view)
        assert bool(check_edit)

    for _ in role_provider.to_be_badguy():
        assert not bool(check_view)
        assert not bool(check_edit)
