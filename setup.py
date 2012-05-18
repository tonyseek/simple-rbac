#!/usr/bin/env python
#-*- coding:utf-8 -*-

import setuptools


metadata = {'name': "Simple RBAC",
            'version': "0.1",
            'description': "A simple role based access control utility",
            'keywords': "rbac permission acl access-control",
            'author': "TonySeek",
            'author_email': "tonyseek@gmail.com",
            'url': "http://tonyseek.github.com/simple-rbac/",
            'license': "MIT License",
            'packages': ["rbac"],
            'zip_safe': True,
            'platforms': "any",
            'test_suite': "tests.run_tests"}


if __name__ == "__main__":
    setuptools.setup(**metadata)
