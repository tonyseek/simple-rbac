#!/usr/bin/env python
#-*- coding:utf-8 -*-

import setuptools


metadata = {'name': "Simple RBAC",
            'version': "0.1",
            'packages': ["rbac"],
            'author': "TonySeek",
            'author_email': "tonyseek@gmail.com",
            'license': "MIT",
            'test_suite': "tests.run_tests"}


if __name__ == "__main__":
    setuptools.setup(**metadata)
