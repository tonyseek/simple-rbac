#!/usr/bin/env python
#-*- coding:utf-8 -*-

import unittest

import rbac.acl
import rbac.context


class ContextTestCase(unittest.TestCase):

    def setUp(self):
        self.acl = rbac.acl.Registry()
        self.context = rbac.context.IdentityContext(self.acl)

    def test_simple(self):
        pass  # TODO: give me some tests
