Simple RBAC
===========

This is a simple role based control access utility in Python.


Quick Start
-----------

### 1. Install Simple RBAC

```sh
pip install git+git://github.com/tonyseek/simple-rbac.git
```

### 2. Create a Access Control List

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

### 5. Use It to Check Permission

```python
if acl.is_allowed("student", "view", "course"):
    print("Students chould view courses.")
else:
    print("Students chould not view courses.")

if acl.is_allowed("junior-student", "learn", "senior-course"):
    print("Junior students chould learn courses.")
else:
    print("Junior students chould not learn courses.")
```


Custom Role and Resource Class
------------------------------

It's not necessary to use string as role object and resource object like
"Quick Start". You could define role class and resource class of yourself,
such as a database mapped model in SQLAlchemy.

Whatever which role class and resource class you will use, it must implement
`__hash__` method and `__eq__` method to be [hashable][0].

### Example

```python
class Role(db.Model):
    """The role."""

    id = db.Column(db.Integer, primary_key=True)
    screen_name = db.Column(db.Unicode, nullable=False, unique=True)

    def __hash__(self):
        return hash("ROLE::%d" % self.id)

    def __eq__(self, other):
        return self.id == other.id


class Resource(db.Model):
    """The resource."""

    id = db.Column(db.Integer, primary_key=True)
    screen_name = db.Column(db.Unicode, nullable=False, unique=True)

    def __hash__(self):
        return hash("RESOURCE::%d" % self.id)

    def __eq__(self, other):
        return self.id == other.id
```


[0]: "http://docs.python.org/glossary.html#term-hashable", "Hashable"
