Simple RBAC
===========

This is a simple role based control access utility in Python.


Quick Start
-----------

### 1. Install Simple RBAC

```sh
pip install git+git://github.com/tonyseek/simple-rbac.git
```

### 2. Create A Access Control List

```python
import rbac.acl

acl = rbac.acl.Registry()
```

### 3. Register Roles and Resources

```python
acl.add_role("member")
acl.add_role("student", ["member"])
acl.add_role("teacher", ["member"])
acl.add_role("junior-student", ["student"])

acl.add_resource("course")
acl.add_resource("senior-course", ["course"])
```

### 4. Add Rules

```python
acl.allow("member", "view", "course")
acl.allow("student", "learn", "course")
acl.allow("teacher", "teach", "course")
acl.deny("junior-student", "learn", "senior-course")
```

### 5. Use It To Check Permission

```python
if acl.is_allowed("student", "view", "course"):
    print("Students chould view courses.")
else:
    print("Students chould not view courses.")


if acl.is_allowed("junior-student", "learn", "senior-course"):
    print("Junior students chould learn courses.")
else:
    print("Junior students chould not learn courses.")
"""
