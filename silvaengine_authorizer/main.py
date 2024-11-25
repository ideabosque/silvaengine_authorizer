#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from .authorizer.handlers import verify_permission, authorize_response, authorize_websocket

__author__ = "bl"


class Authorizer(object):
    def __init__(self, logger):
        self.logger = logger

    # Authorize token
    def authorize(self, event, context):
        try:
            if event.get("requestContext",{}).get("eventType") == 'CONNECT':
                return authorize_websocket(event, context, self.logger)
            return authorize_response(event, context, self.logger)
        except Exception as e:
            raise e

    # Authorize user permissions
    def verify_permission(self, event, context):
        try:
            return verify_permission(event, context, self.logger)
        except Exception as e:
            raise e
