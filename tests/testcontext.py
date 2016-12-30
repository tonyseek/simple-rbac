#!/usr/bin/env python
# -*- coding:utf-8 -*-

import unittest

import rbac.acl
import rbac.context


class ContextTestCase(unittest.TestCase):

    def setUp(self):
        # create context
        self.acl = rbac.acl.Registry()
        self.context = rbac.context.IdentityContext(self.acl)
        self.denied_error = rbac.context.PermissionDenied

        # register roles and resources
        self.acl.add_role("staff")
        self.acl.add_role("editor", parents=["staff"])
        self.acl.add_role("badguy", parents=["staff"])
        self.acl.add_resource("article")

        # add rules
        self.acl.allow("staff", "view", "article")
        self.acl.allow("editor", "edit", "article")
        self.acl.deny("badguy", None, "article")

    def test_decorator(self):
        @self.context.check_permission("view", "article")
        def view_article():
            return True

        @self.context.check_permission("edit", "article")
        def edit_article():
            return True

        self._assert_call(view_article, edit_article)

    def test_with_statement(self):
        def view_article():
            with self.context.check_permission("view", "article"):
                return True

        def edit_article():
            with self.context.check_permission("edit", "article"):
                return True

        self._assert_call(view_article, edit_article)

    def test_check_function(self):
        check_view = self.context.check_permission("view", "article").check
        check_edit = self.context.check_permission("edit", "article").check
        self._assert_call(check_view, check_edit)

    def test_nonzero(self):
        check_view = self.context.check_permission("view", "article")
        check_edit = self.context.check_permission("edit", "article")

        for _ in self._to_be_staff():
            self.assertTrue(bool(check_view))
            self.assertFalse(bool(check_edit))

        for _ in self._to_be_editor():
            self.assertTrue(bool(check_view))
            self.assertTrue(bool(check_edit))

        for _ in self._to_be_badguy():
            self.assertFalse(bool(check_view))
            self.assertFalse(bool(check_edit))

    # -------------------
    # Composite Assertion
    # -------------------

    def _assert_call(self, view_article, edit_article):
        for _ in self._to_be_staff():
            self.assertTrue(view_article())
            self.assertRaises(self.denied_error, edit_article)

        for _ in self._to_be_editor():
            self.assertTrue(view_article())
            self.assertTrue(edit_article())

        for _ in self._to_be_badguy():
            self.assertRaises(self.denied_error, view_article)
            self.assertRaises(self.denied_error, edit_article)

    # --------------
    # Role Providers
    # --------------

    def _to_be_staff(self):
        @self.context.set_roles_loader
        def load_roles():
            yield "staff"

        yield 0

    def _to_be_editor(self):
        @self.context.set_roles_loader
        def load_roles_0():
            yield "editor"

        yield 0

        @self.context.set_roles_loader
        def load_roles_1():
            yield "staff"
            yield "editor"

        yield 1

    def _to_be_badguy(self):
        @self.context.set_roles_loader
        def load_roles_0():
            yield "badguy"

        yield 0

        @self.context.set_roles_loader
        def load_roles_1():
            yield "staff"
            yield "badguy"

        yield 1

        @self.context.set_roles_loader
        def load_roles_2():
            yield "editor"
            yield "badguy"

        yield 2

        @self.context.set_roles_loader
        def load_roles_3():
            yield "staff"
            yield "editor"
            yield "badguy"

        yield 3
