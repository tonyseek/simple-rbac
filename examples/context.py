#!/usr/bin/env python
#-*- coding:utf-8 -*-

from rbac.acl import Registry
from rbac.context import IdentityContext, PermissionDenied


# -----------------------------------------------
# build the access control list and add the rules
# -----------------------------------------------

acl = Registry()
context = IdentityContext(acl)

acl.add_role("staff")
acl.add_role("editor", parents=["staff"])
acl.add_role("bad man", parents=["staff"])
acl.add_resource("article")

acl.allow("staff", "view", "article")
acl.allow("editor", "edit", "article")
acl.deny("bad man", None, "article")


# -------------
# to be a staff
# -------------

@context.set_roles_loader
def first_load_roles():
    yield "staff"

print "Now you are %s." % ", ".join(context.load_roles())


@context.check_permission("view", "article", message="can not view")
def article_page():
    return "<view>"


@context.check_permission("edit", "article", message="can not edit")
def edit_article_page():
    return "<edit>"


if article_page() == "<view>":
    print "You could view the article page."

try:
    edit_article_page()
except PermissionDenied as exception:
    print "You could not edit the article page,",
    print "the exception said: '%s'." % exception.kwargs['message']


# --------------
# to be a editor
# --------------

@context.set_roles_loader
def second_load_roles():
    yield "editor"

print "Now you are %s." % ", ".join(context.load_roles())

if edit_article_page() == "<edit>":
    print "You could edit the article page."


# ---------------
# to be a bad man
# ---------------

@context.set_roles_loader
def third_load_roles():
    yield "bad man"

print "Now you are %s." % ", ".join(context.load_roles())

try:
    article_page()
except PermissionDenied as exception:
    print "You could not view the article page,",
    print "the exception said: '%s'." % exception.kwargs['message']
