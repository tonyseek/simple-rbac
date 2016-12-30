#!/usr/bin/env python
# -*- coding:utf-8 -*-

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from rbac.acl import Registry
from rbac.proxy import RegistryProxy
from rbac.context import IdentityContext, PermissionDenied


engine = create_engine('sqlite:///:memory:', echo=False)
Session = sessionmaker(bind=engine)
ModelBase = declarative_base()


class ResourceMixin(object):

    def __eq__(self, other):
        return hasattr(other, "id") and self.id == other.id

    def __hash__(self):
        return hash(self.id)


class User(ResourceMixin, ModelBase):
    """User Model"""

    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    roles = Column(String, nullable=False, default="")

    def get_roles(self):
        return self.roles.split(",")

    def set_roles(self, roles):
        self.roles = ",".join(roles)


class Message(ResourceMixin, ModelBase):
    """Message Model"""

    __tablename__ = "post"
    id = Column(Integer, primary_key=True)
    content = Column(String, nullable=False)
    owner_id = Column(ForeignKey(User.id), nullable=False)
    owner = relationship(User, uselist=False, lazy="joined")


def main():
    # current context user
    current_user = None

    # create a access control list
    acl = RegistryProxy(Registry())
    identity = IdentityContext(acl, lambda: current_user.get_roles())

    # registry roles and resources
    acl.add_role("staff")
    acl.add_role("admin")
    acl.add_resource(Message)

    def check(acl, role, operation, resource):
        return db.query(Message).get(resource.id).owner is current_user

    is_message_owner = check
    acl.allow("staff", "create", Message)
    acl.allow("staff", "edit", Message, assertion=is_message_owner)
    acl.allow("admin", "edit", Message)

    db = Session()
    ModelBase.metadata.create_all(engine)

    tonyseek = User(name="tonyseek")
    tonyseek.set_roles(["staff"])
    tom = User(name="tom")
    tom.set_roles(["staff"])
    admin = User(name="admin")
    admin.set_roles(["admin"])
    db.add_all([tonyseek, tom, admin])
    db.commit()

    @identity.check_permission("create", Message)
    def create_message(content):
        message = Message(content=content, owner=current_user)
        db.add(message)
        db.commit()
        print "%s has craeted a message: '%s'." % (
            current_user.name.capitalize(), content)

    def edit_message(content, new_content):
        message = db.query(Message).filter_by(content=content).one()

        if not identity.check_permission("edit", message):
            print "%s tried to edit the message '%s' but he will fail." % (
                current_user.name.capitalize(), content)
        else:
            print "%s will edit the message '%s'." % (
                current_user.name.capitalize(), content)

        with identity.check_permission("edit", message):
            message.content = new_content
            db.commit()

        print "The message '%s' has been edit by %s," % \
            (content, current_user.name.capitalize()),
        print "the new content is '%s'" % new_content

    # tonyseek signed in and create a message
    current_user = tonyseek
    create_message("Please open the door.")

    # tom signed in and edit tonyseek's message
    current_user = tom
    try:
        edit_message("Please open the door.", "Please don't open the door.")
    except PermissionDenied:
        print "Oh, the operation has been denied."

    # tonyseek signed in and edit his message
    current_user = tonyseek
    edit_message("Please open the door.", "Please don't open the door.")

    # admin signed in and edit tonyseek's message
    current_user = admin
    edit_message("Please don't open the door.", "Please open the window.")


if __name__ == "__main__":
    main()
