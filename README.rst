Simple RBAC
===========

This is a simple role based access control utility in Python.

Quick Start
-----------

1. Install Simple RBAC
~~~~~~~~~~~~~~~~~~~~~~

::

    pip install simple-rbac

2. Create a Access Control List
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    import rbac.acl

    acl = rbac.acl.Registry()

3. Register Roles and Resources
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    acl.add_role("member")
    acl.add_role("student", ["member"])
    acl.add_role("teacher", ["member"])
    acl.add_role("junior-student", ["student"])

    acl.add_resource("course")
    acl.add_resource("senior-course", ["course"])

4. Add Rules
~~~~~~~~~~~~

::

    acl.allow("member", "view", "course")
    acl.allow("student", "learn", "course")
    acl.allow("teacher", "teach", "course")
    acl.deny("junior-student", "learn", "senior-course")

5. Use It to Check Permission
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    if acl.is_allowed("student", "view", "course"):
        print("Students chould view courses.")
    else:
        print("Students chould not view courses.")

    if acl.is_allowed("junior-student", "learn", "senior-course"):
        print("Junior students chould learn senior courses.")
    else:
        print("Junior students chould not learn senior courses.")

Custom Role and Resource Class
------------------------------

It’s not necessary to use string as role object and resource object like
"Quick Start". You could define role class and resource class of
yourself, such as a database mapped model in SQLAlchemy.

Whatever which role class and resource class you will use, it must
implement ``__hash__`` method and ``__eq__`` method to be `hashable`_.

Example
~~~~~~~

::

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

Of course, You could use the built-in hashable types too, such as tuple,
namedtuple, frozenset and more.

Use the Identity Context Check Your Permission
----------------------------------------------

Obviously, the work of checking permission is a cross-cutting concern.
The module named ``rbac.context``, our ``IdentityContext``, provide some
ways to make our work neater.

1. Create the Context Manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    acl = Registry()
    context = IdentityContext(acl)

2. Set a Loader
~~~~~~~~~~~~~~~

The loader should load the roles of current user.

::

    from myapp import get_current_user

    @context.set_roles_loader
    def second_load_roles():
        user = get_current_user()
        yield "everyone"
        for role in user.roles:
            yield str(role)

3. Protect Your Action
~~~~~~~~~~~~~~~~~~~~~~

Now you could protect your action from unauthorized access. As you
please, you could choose many ways to check the permission, including
python ``decorator``, python ``with statement`` or simple method
calling.

Decorator
^^^^^^^^^

::

    @context.check_permission("view", "article", message="can't view")
    def article_page():
        return "your-article"

With Statement
^^^^^^^^^^^^^^

::

    def article_page():
        with context.check_permission("view", "article", message="can't view"):
            return "your-article"

Simple Method Calling
^^^^^^^^^^^^^^^^^^^^^

::

    def article_page():
        context.check_permission("view", "article", message="can't view").check()
        return "your-article"

Exception Handler and Non-Zero Checking
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Whatever which way you choosen, a exception
``rbac.context.PermissionDenied`` will be raised while a unauthorized
access happening. The keyword arguments sent to the
``context.check_permission`` will be set into a attirbute named
``kwargs`` of the exception. You could get those data in your exception
handler.

::

    @context.check_permission("view", "article", message="can not view")
    def article_page():
        return "your-article"

    try:
        print article_page()
    except PermissionDenied as exception:
        print "The access has been denied, you %s" % exception.kwargs['message']

If you don’t want to raise the exception but only check the access is
allowed or not, you could use the checking like a boolean value.

::

    if not context.check_permission("view", "article"):
        print "Oh! the access has been denied."

    is_allowed = bool(context.check_permission("view", "article"))

.. _hashable: http://docs.python.org/glossary.html#term-hashable
