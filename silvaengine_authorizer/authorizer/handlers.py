#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from jose import jwt
from silvaengine_utility import Utility, Graphql, Authorizer
from silvaengine_base import ConnectionsModel, LambdaBase
from .enumerations import SwitchStatus
from datetime import datetime
import json, time, jsonpickle

def runtime_debug(endpoint_id="", t=0, mark=""):
    d=int(datetime.now().timestamp() * 1000) - t
    if str(endpoint_id).strip().lower() == "ss3" and d > 0:
        print("############# It took {} ms to execute request `{}`.".format(d, mark))
    
    return int(datetime.now().timestamp() * 1000)

###############################################################################
# Verify ip whitelist.
###############################################################################
def _verify_whitelist(event, context) -> bool:
    try:
        identity = event.get("requestContext", {}).get("identity", {})
        endpoint_id = event.get("pathParameters", {}).get("endpoint_id")
        api_key = identity.get("apiKey")
        source_ip = identity.get("sourceIp")

        if not source_ip or not api_key or not endpoint_id:
            return False

        endpoint_id = str(endpoint_id).strip()
        api_key = str(api_key).strip()
        source_ip = str(source_ip).strip()
        connnection = ConnectionsModel.get(endpoint_id, api_key)

        if type(connnection.whitelist) is list and len(connnection.whitelist):
            whitelist = list(set(connnection.whitelist))

            for ip in whitelist:
                return Utility.in_subnet(source_ip, ip.strip())

        return False
    except Exception as e:
        raise e


###############################################################################
# Verify token.
###############################################################################
def _verify_token(settings, event) -> dict:
    claims = None

    try:
        headers = dict(
            (key.strip().lower(), value)
            for key, value in event.get("headers", {}).items()
        )
        token = headers.get("authorization")

        if not token:
            raise Exception(f"Token is required", 400)

        claims = jwt.get_unverified_claims(str(token).strip())
        required_setting_keys = ["region_name", "user_pool_id", "app_client_id"]

        for key in required_setting_keys:
            if settings.get(key) is None:
                raise Exception(f"Missing configuration item `{key}`", 400)

        # additionally we can verify the token expiration
        if time.time() > claims["exp"]:
            raise Exception("Token is expired", 401)

        return claims
    except Exception as e:
        raise e


###############################################################################
# Execute custom hooks by setting.
###############################################################################
def _execute_hooks(
    hooks,
    function_parameters=None,
    constructor_parameters=None,
    endpoint_id=None,
    api_key=None,
    method=None,
    context=None,
):
    try:
        results = {"dict": {}, "list": []}

        if hooks:
            hooks = [str(hook).strip() for hook in str(hooks).split(",")]
            # @TODO: exec by async
            for hook in hooks:
                fragments = hook.split(":", 3)

                if len(fragments) < 3:
                    for i in (0, 3 - len(fragments)):
                        fragments.append(None)
                elif len(fragments) > 3:
                    fragments = fragments[0:3]

                module_name, class_name, function_name = fragments

                # Load module by dynamic
                fn = Utility.import_dynamically(
                    module_name=module_name,
                    function_name=function_name,
                    class_name=class_name,
                    constructor_parameters=constructor_parameters,
                )

                if callable(fn):
                    result = fn(
                        **(
                            function_parameters
                            if type(function_parameters) is dict
                            and len(function_parameters)
                            else {}
                        )
                    )

                    if not Utility.is_json_string(result):
                        result = jsonpickle.encode(result, unpicklable=False)
                    # else:
                    #     result = Utility.json_loads(
                    #         Utility.json_dumps(result), parser_number=False
                    #     )
                    result = jsonpickle.decode(result)

                    if type(result) is dict:
                        results["dict"].update(result)
                    elif type(result) is list:
                        results["list"] += result
                elif endpoint_id and api_key:
                    try:
                        settings, function = LambdaBase.get_function(
                            endpoint_id=endpoint_id,
                            funct=function_name,
                            api_key=api_key,
                            method=method,
                        )

                        if function:
                            payload = {
                                "MODULENAME": str(function.config.module_name).strip(),
                                "CLASSNAME": str(function.config.class_name).strip(),
                                "funct": str(function.function).strip(),
                                "setting": json.dumps(settings),
                                "params": json.dumps(
                                    function_parameters
                                    if type(function_parameters) is dict
                                    and len(function_parameters)
                                    else {}
                                ),
                                "body": None,
                                # "context": Utility.json_dumps(context),
                                "context": jsonpickle.encode(context, unpicklable=False),
                            }
                            # invoke(cls, function_name, payload, invocation_type="Event"):
                            result = LambdaBase.invoke(
                                function_name=function.aws_lambda_arn,
                                payload=payload,
                                invocation_type=str(function.config.funct_type).strip(),
                            )

                            if not Utility.is_json_string(result):
                                # result = Utility.json_loads(result, parser_number=False)
                                result = jsonpickle.encode(result, unpicklable=False)

                            result = jsonpickle.decode(result)

                            if type(result) is dict:
                                results["dict"].update(result)
                            elif type(result) is list:
                                results["list"] += result
                    except:
                        pass

        return results
    except Exception as e:
        raise e


###############################################################################
# Check the access rights of the specified role to the specified resource.
###############################################################################
def _check_permission(roles, resource) -> bool:
    if (
        not resource.get("operation")
        or not resource.get("operation_name")
        or not resource.get("fields")
    ):
        return False

    permissions = []

    for role in roles:
        if (
            not role.get("permissions")
            or not role.get("role_id")
            or type(role.get("permissions")) is not list
            or len(role.get("permissions")) < 1
        ):
            continue

        permissions += role.get("permissions")

    rules = []

    for permission in permissions:
        if (
            not permission.get("permissions")
            or not permission.get("resource_id")
            or type(permission.get("permissions")) is not list
            or len(permission.get("permissions")) < 1
        ):
            continue

        rules += permission.get("permissions")

    m = {}
    request_operation = str(resource.get("operation", "")).strip().lower()
    request_operation_name = str(resource.get("operation_name", "")).strip().lower()
    request_fields = resource.get("fields")

    for rule in rules:
        if (
            not rule.get("operation")
            or not rule.get("operation_name")
            or request_operation != str(rule.get("operation")).strip().lower()
        ):
            continue

        operation_name = str(rule.get("operation_name")).strip().lower()

        if not m.get(operation_name):
            m[operation_name] = []

        if type(rule.get("exclude")) is list and len(rule.get("exclude")):
            m[operation_name] = list(set(m[operation_name] + rule.get("exclude")))

    if type(m.get(request_operation_name)) is list:
        for field in m.get(request_operation_name):
            path, field = str(field).strip().lower().split(":", 2)

            if (
                path
                and field
                and path != ""
                and field != ""
                and request_fields.get(path)
                and field.strip().lower() in request_fields.get(path)
            ):
                return False
        return True
    return False


###############################################################################
# Check the current request permission verification.
###############################################################################
def _is_authorize_required(event):
    config = event.get("fnConfigurations", {}).get("config", {})

    if type(config.get("auth_required")) is bool:
        return config.get("auth_required")

    return bool(int(str(config.get("auth_required", 0)).strip()))


###############################################################################
# Check the current request allowed by whitelist.
###############################################################################
def _is_whitelisted(event):
    authorizer = event.get("requestContext", {}).get("authorizer", {})

    if type(authorizer.get("is_allowed_by_whitelist")) is bool:
        return authorizer.get("is_allowed_by_whitelist")

    return bool(int(str(authorizer.get("is_allowed_by_whitelist", 0)).strip()))


###############################################################################
# Permission verification response.
###############################################################################
def authorize_response(event, context, logger):
    try:
        headers = dict(
            (key.strip().lower(), value)
            for key, value in event.get("headers", []).items()
        )
        principal = event.get("path", "/")
        api_id = event.get("requestContext", {}).get("apiId")
        api_key = event.get("requestContext", {}).get("identity", {}).get("apiKey","KwhtmyYf2u9JuGvHELx2BwpsQGkYkocayXWX2Rq1")
        arn = event.get("methodArn")
        method_arn_fragments = event.get("methodArn").split(":")
        api_gateway_arn_fragments = method_arn_fragments[5].split("/")
        region = method_arn_fragments[3]
        aws_account_id = method_arn_fragments[4]
        stage = api_gateway_arn_fragments[1]
        area = api_gateway_arn_fragments[3]
        # Use `endpoint_id` to differentiate app channels
        endpoint_id = api_gateway_arn_fragments[4]

        if not principal.startswith("/{}".format(stage)):
            principal = "/{}{}".format(stage, principal)

        if endpoint_id is None:
            raise Exception("Unrecognized request origin", 401)
        
        authorizer = Authorizer(principal, aws_account_id, api_id, region, stage)
        setting_key = f"{stage}_{area}_{endpoint_id}"
        settings = LambdaBase.get_setting(setting_key)

        if len(settings.keys()) < 1:
            raise Exception(f"Missing required configuration(s) `{setting_key}`", 500)
        elif settings.get("user_source") is None:
            raise Exception(
                f"Configuration item `{setting_key}` is missing variable `user_source`",
                400,
            )

        ctx = dict(
            {"user_source": int(settings.get("user_source"))},
            **{"custom_context_hooks": settings.get("custom_context_hooks")}
            if settings.get("custom_context_hooks")
            else {},
            **{"seller_id": str(headers.get("seller_id")).strip()}
            if headers.get("seller_id")
            else {},
            **{"team_id": str(headers.get("team_id")).strip()}
            if headers.get("team_id")
            else {},
        )
        # request_method = str(event.get("requestContext").get("httpMethod")).upper()

        # 1. Skip authorize ############################################################
        if int(settings.get("skip_authorize", 0)):
            return authorizer.authorize(is_allow=True, context=ctx)

        # 2. Verify source ip ############################################################
        if _verify_whitelist(event, context):
            ctx.update(
                {
                    "is_allowed_by_whitelist": SwitchStatus.YES.value,
                }
            )

            return authorizer.authorize(is_allow=True, context=ctx)

        # 3. Verify user token ############################################################
        if _is_authorize_required(event):
            claims = _verify_token(settings, event)

            if not claims:
                raise Exception("Invalid token", 400)

            if settings.get("after_token_parsed_hooks"):
                claims.update(
                    _execute_hooks(
                        hooks=str(settings.get("after_token_parsed_hooks")).strip(),
                        function_parameters={
                            "claims": claims,
                            "context": ctx,
                        },
                        constructor_parameters={"logger": logger},
                        endpoint_id=endpoint_id,
                        # endpoint_id=claims.get("from",endpoint_id),
                        api_key=api_key,
                        context=event.get("requestContext", {}),
                    ).get("dict", {})
                )
            
            claims.update(ctx)
            return authorizer.authorize(is_allow=True, context=claims)

        return authorizer.authorize(is_allow=True, context=ctx)
    except Exception as e:
        raise e


###############################################################################
# Verify resource permission
###############################################################################
def verify_permission(event, context, logger):
    try:
        ts = runtime_debug()
        if not _is_authorize_required(event) or _is_whitelisted(event):
            return event
        elif (
            not event.get("pathParameters", {}).get("proxy")
            or not event.get("headers")
            or not event.get("body")
            or not event.get("fnConfigurations")
            or not event.get("requestContext", {}).get("authorizer", {}).get("user_id")
        ):
            raise Exception("Event is missing required parameters", 500)

        headers = dict(
            (key.strip().lower(), value)
            for key, value in event.get("headers", []).items()
        )
        function_config = event.get("fnConfigurations")
        authorizer = event.get("requestContext", {}).get("authorizer")
        api_key = event.get("requestContext", {}).get("identity", {}).get("apiKey")
        body = event.get("body")
        function_name = event.get("pathParameters", {}).get("proxy").strip()
        content_type = headers.get("content-type", "")
        stage = event.get("requestContext", {}).get("stage")
        area = event.get("pathParameters", {}).get("area")
        endpoint_id = event.get("pathParameters", {}).get("endpoint_id")
        is_admin = bool(int(str(authorizer.get("is_admin", 0)).strip()))
        uid = str(authorizer.get("user_id")).strip()  # uid = authorizer.get("sub")
        # owner_id = str(authorizer.get("seller_id")).strip()
        group_id = str(authorizer.get("team_id")).strip()
        token_issuer = str(authorizer.get("from",endpoint_id)).strip()
        # method = event["httpMethod"]
        function_operations = function_config.get("config", {}).get("operations")
        module_name = function_config.get("config", {}).get("module_name")
        class_name = function_config.get("config", {}).get("class_name")
        message = f"Don't have the permission to access at /{area}/{endpoint_id}/{function_name}."
        setting_key = f"{stage}_{area}_{endpoint_id}"
        settings = LambdaBase.get_setting(setting_key)

        if not function_operations or not module_name or not class_name or not uid:
            raise Exception(message, 403)
        elif len(settings.keys()) < 1:
            raise Exception(f"Missing required configuration(s) `{setting_key}`", 500)
        elif not settings.get("permission_check_hooks"):
            raise Exception(f"Missing configuration item `permission_check_hooks`", 400)

        if str(content_type).strip().lower() == "application/json":
            body_json = json.loads(body)

            if "query" in body_json:
                body = body_json["query"]

        ts=runtime_debug(endpoint_id=endpoint_id, ts=ts, mark="{}:extract paramenters from event".format(function_name))

        # Parse the graphql request's body to AST and extract fields from the AST
        flatten_ast = Graphql.extract_flatten_ast(body)

        ts=runtime_debug(endpoint_id=endpoint_id, ts=ts, mark="{}:extract_flatten_ast".format(function_name))
        if type(flatten_ast) is not list or len(flatten_ast) < 1:
            raise Exception(message, 403)

        roles = _execute_hooks(
            hooks=str(settings.get("permission_check_hooks")).strip(),
            function_parameters={
                "user_id": str(uid).strip(),
                # "channel": endpoint_id,
                "channel": token_issuer,
                "is_admin": is_admin,
                "group_id": group_id,
            },
            constructor_parameters={"logger": logger},
            # endpoint_id=endpoint_id,
            endpoint_id=token_issuer,
            api_key=api_key if token_issuer == endpoint_id else "#####",
            context=event.get("requestContext", {}),
        ).get("list")

        ts=runtime_debug(endpoint_id=endpoint_id, ts=ts, mark="{}:permission_check_hooks".format(function_name))

        if len(roles) < 1:
            raise Exception(message, 403)

        for item in flatten_ast:
            if not item.get("operation_name"):
                default = ""
                root = item.get("fields", {}).get("/")

                if type(root) is list and len(root):
                    default = root[0]

                item["operation_name"] = default

            operation_name = item.get("operation_name", "")
            operation = item.get("operation", "")

            # Check the operation type is be included by function settings
            if (
                not function_operations.get(operation)
                or type(function_operations.get(operation)) is not list
            ):
                raise Exception(message, 403)

            function_operations = list(
                set(
                    [
                        operation_name.strip().lower()
                        for operation_name in function_operations.get(operation)
                    ]
                )
            )

            if (
                operation_name.strip().lower() not in function_operations
            ) or not _check_permission(roles, item):
                raise Exception(message, 403)
            ts=runtime_debug(endpoint_id=endpoint_id, ts=ts, mark="{}:map_flatten_ast".format(function_name))

        ts=runtime_debug(endpoint_id=endpoint_id, ts=ts, mark="{}:check_permission".format(function_name))
        # Attatch additional info to context
        additional_context = {
            "roles": [
                {
                    "role_id": str(role.get("role_id")).strip(),
                    "name": str(role.get("name")).strip(),
                }
                for role in roles
            ]
        }

        # Append hooks result to context
        if authorizer.get("custom_context_hooks"):
            additional_context.update(
                _execute_hooks(
                    hooks=str(authorizer.get("custom_context_hooks")).strip(),
                    function_parameters={"authorizer": authorizer},
                    constructor_parameters={"logger": logger},
                    endpoint_id=endpoint_id,
                    api_key=api_key,
                    context=event.get("requestContext", {}),
                ).get("dict", {})
            )

        event["requestContext"]["additionalContext"] = additional_context

        if type(context) is dict and len(context):
            event["requestContext"]["authorizer"].update(context)

        ts=runtime_debug(endpoint_id=endpoint_id, ts=ts, mark="{}:custom_context_hooks".format(function_name))
        return event
    except Exception as e:
        raise e
