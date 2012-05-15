#!/usr/bin/env python
#-*- coding:utf-8 -*-

import unittest

import rbac.acl


class RBACAclTestCase(unittest.TestCase):
    """The test case of rbac.acl module."""

    def setUp(self):
        # create acl registry
        self.acl = rbac.acl.Registry()

        # add roles
        self.acl.add_role("user")
        self.acl.add_role("actived_user", parents=["user"])
        self.acl.add_role("writer", parents=["actived_user"])
        self.acl.add_role("manager", parents=["actived_user"])
        self.acl.add_role("editor", parents=["writer", "manager"])
        self.acl.add_role("super")

        # add resources
        self.acl.add_resource("comment")
        self.acl.add_resource("post")
        self.acl.add_resource("news", parents=["post"])
        self.acl.add_resource("infor", parents=["post"])
        self.acl.add_resource("event", parents=["news"])

        # set super permission
        self.acl.allow("super", None, None)

    def test_allow(self):
        # add allowed rules
        self.acl.allow("actived_user", "view", "news")
        self.acl.allow("writer", "new", "news")

        # test "view" operation
        roles = ["actived_user", "writer", "manager", "editor"]

        for role in roles:
            for resource in ["news", "event"]:
                self.assertTrue(self.acl.is_allowed(role, "view", resource))
            for resource in ["post", "infor"]:
                self.assertFalse(self.acl.is_allowed(role, "view", resource))

        for resource in ["news", "event"]:
            self.assertTrue(self.acl.is_any_allowed(roles, "view", resource))
        for resource in ["post", "infor"]:
            self.assertFalse(self.acl.is_any_allowed(roles, "view", resource))

        for resource in ["post", "news", "infor", "event"]:
            self.assertFalse(self.acl.is_allowed("user", "view", resource))
            self.assertTrue(self.acl.is_allowed("super", "view", resource))
            self.assertTrue(self.acl.is_allowed("super", "new", resource))
            self.assertTrue(self.acl.is_any_allowed(["user", "super"],
                "view", resource))


        # test "new" operation
        roles = ["writer", "editor"]

        for role in roles:
            for resource in ["news", "event"]:
                self.assertTrue(self.acl.is_allowed(role, "new", resource))
            for resource in ["post", "infor"]:
                self.assertFalse(self.acl.is_allowed(role, "new", resource))

        for resource in ["news", "event"]:
            self.assertTrue(self.acl.is_any_allowed(roles, "new", resource))
        for resource in ["post", "infor"]:
            self.assertFalse(self.acl.is_any_allowed(roles, "new", resource))


        roles = ["user", "manager"]

        for role in roles:
            for resource in ["news", "event", "post", "infor"]:
                self.assertFalse(self.acl.is_allowed(role, "new", resource))
        for resource in ["news", "event", "post", "infor"]:
            self.assertFalse(self.acl.is_any_allowed(roles, "new", resource))

    def test_deny(self):
        # add allowed rule and denied rule
        self.acl.allow("actived_user", "new", "comment")
        self.acl.deny("manager", "new", "comment")

        # test allowed rules
        roles = ["actived_user", "writer"]

        for role in roles:
            self.assertTrue(self.acl.is_allowed(role, "new", "comment"))

        self.assertTrue(self.acl.is_any_allowed(roles, "new", "comment"))


        # test denied rules
        roles = ["manager", "editor"]

        for role in roles:
            self.assertFalse(self.acl.is_allowed(role, "new", "comment"))

        self.assertFalse(self.acl.is_any_allowed(roles, "new", "comment"))

    def test_undefined(self):
        # test denied undefined rule
        roles = ["user", "actived_user", "writer", "manager", "editor"]
        
        for resource in ["comment", "post", "news", "infor", "event"]:
            for role in roles:
                self.assertFalse(self.acl.is_allowed(role, "x", resource))
                self.assertFalse(self.acl.is_allowed(role, "", resource))
                self.assertFalse(self.acl.is_allowed(role, None, resource))
            self.assertFalse(self.acl.is_any_allowed(roles, "x", resource))
            self.assertFalse(self.acl.is_any_allowed(roles, "", resource))
            self.assertFalse(self.acl.is_any_allowed(roles, None, resource))

        # test `None` defined rule
        for resource in ["comment", "post", "news", "infor", "event", None]:
            for op in ["undefined", "x", "", None]:
                self.assertTrue(self.acl.is_allowed("super", op, resource))

    def test_assertion(self):
        # set up assertion
        db = {'newsid': 1}
        assertion = lambda acl, role, operation, resource: db['newsid'] == 10

        # set up rules
        self.acl.add_role("writer2", parents=["writer"])
        self.acl.allow("writer", "edit", "news", assertion)
        self.acl.allow("manager", "edit", "news")

        # test while assertion is invalid
        self.assertFalse(self.acl.is_allowed("writer", "edit", "news"))
        self.assertFalse(self.acl.is_allowed("writer2", "edit", "news"))
        self.assertTrue(self.acl.is_allowed("manager", "edit", "news"))
        self.assertTrue(self.acl.is_allowed("editor", "edit", "news"))

        # test while assertion is valid
        db['newsid'] = 10
        self.assertTrue(self.acl.is_allowed("writer", "edit", "news"))
        self.assertTrue(self.acl.is_allowed("editor", "edit", "news"))
        self.assertTrue(self.acl.is_allowed("manager", "edit", "news"))
