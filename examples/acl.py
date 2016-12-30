#!/usr/bin/env python
# -*- coding:utf-8 -*-

import rbac.acl


# create access control list
acl = rbac.acl.Registry()

# add roles
acl.add_role("member")
acl.add_role("student", ["member"])
acl.add_role("teacher", ["member"])
acl.add_role("junior-student", ["student"])

# add resources
acl.add_resource("course")
acl.add_resource("senior-course", ["course"])

# set rules
acl.allow("member", "view", "course")
acl.allow("student", "learn", "course")
acl.allow("teacher", "teach", "course")
acl.deny("junior-student", "learn", "senior-course")

# use acl to check permission
if acl.is_allowed("student", "view", "course"):
    print("Students chould view courses.")
else:
    print("Students chould not view courses.")

# use acl to check permission again
if acl.is_allowed("junior-student", "learn", "senior-course"):
    print("Junior students chould learn senior courses.")
else:
    print("Junior students chould not learn senior courses.")
