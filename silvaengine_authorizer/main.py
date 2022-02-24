#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from .authorizer.handlers import (
    verify_permission,
    authorize_response,
    get_user_permissions,
    check_user_permissions,
)

__author__ = "bl"


class Authorizer(object):
    def __init__(self, logger):
        self.logger = logger

    # Authorize token
    def authorize(self, event, context):
        try:
            return authorize_response(event, context)
        except Exception as e:
            raise e

    # Authorize user permissions
    def verify_permission(self, event, context):
        try:
            return verify_permission(event, context)
        except Exception as e:
            raise e

    # Get permissions by user ID
    def get_permissions(self, user_id, is_admin=0):
        try:
            return get_user_permissions(user_id, is_admin)
        except Exception as e:
            raise e

    # Authorize user permissions
    def check_permission(
        self,
        module_name,
        class_name,
        function_name,
        operation_type,
        operation,
        relationship_type,
        user_id,
        group_id,
    ):
        try:
            return check_user_permissions(
                module_name,
                class_name,
                function_name,
                operation_type,
                operation,
                relationship_type,
                user_id,
                group_id,
            )
        except Exception as e:
            raise e
