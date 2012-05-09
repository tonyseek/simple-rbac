#!/usr/bin/env python
#-*- coding:utf-8 -*-

import unittest


def run_tests():
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    return suite
