#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from jose import jwk, jwt
from jose.utils import base64url_decode
from jose.constants import ALGORITHMS
from hashlib import md5
from importlib.util import find_spec
from importlib import import_module
from silvaengine_utility import Utility, Graphql, Authorizer
from silvaengine_resource import ResourceModel
from .enumerations import SwitchStatus
from .models import (
    ConnectionModel,
    RelationshipModel,
    RoleModel,
    ConfigDataModel,
)
import uuid, json, time, urllib.request, os

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
        connnection = ConnectionModel.get(endpoint_id, api_key)

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

        # keys_url = (
        #     "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json".format(
        #         settings.get("region_name"), settings.get("user_pool_id")
        #     )
        # )

        # print(keys_url)

        # # instead of re-downloading the public keys every time
        # # we download them only on cold start
        # # https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
        # with urllib.request.urlopen(keys_url) as f:
        #     response = f.read()

        # print(response)
        # keys = json.loads(response.decode("utf-8"))["keys"]
        # print(keys)
        # print("TOKEN:", token)
        # # get the kid from the headers prior to verification
        # headers = jwt.get_unverified_headers(token)
        # kid = headers["kid"]
        # print("KIDKIDKIDKIDKIDKIDKIDKID:", kid)
        # # search for the kid in the downloaded public keys
        # key_index = -1

        # for i in range(len(keys)):
        #     if kid == keys[i]["kid"]:
        #         key_index = i
        #         break

        # if key_index == -1:
        #     print("Public key not found in jwks.json")
        #     raise Exception("Public key not found in jwks.json", 401)

        # # construct the public key
        # print(key_index, keys[key_index], type(keys[key_index]))
        # algorithm = (
        #     keys[key_index].get("alg")
        #     if keys[key_index].get("alg")
        #     else ALGORITHMS.RS256
        # )
        # keys[key_index]["alg"] = ALGORITHMS.RS256
        # public_key = jwk.construct(keys[key_index], algorithm)

        # if public_key is None:
        #     raise Exception("Public key is invalid", 401)

        # print(type(public_key), public_key)
        # # get the last two sections of the token,
        # # message and signature (encoded in base64)
        # message, encoded_signature = str(token).rsplit(".", 1)
        # # decode the signature
        # decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))

        # # verify the signature
        # if not public_key.verify(message.encode("utf8"), decoded_signature):
        #     print("Signature verification failed")
        #     raise Exception("Signature verification failed", 401)

        # since we passed the verification, we can now safely
        # use the unverified claims

        # additionally we can verify the token expiration
        if time.time() > claims["exp"]:
            raise Exception("Token is expired", 401)

        # and the Audience  (use claims['client_id'] if verifying an access token)
        app_client_ids = [
            str(id).strip().lower()
            for id in settings.get("app_client_id", "").split(",")
        ]

        if not app_client_ids.__contains__(claims["aud"].strip().lower()):
            raise Exception("Token was not issued for this audience", 401)

        return claims
    except Exception as e:
        raise e


###############################################################################
# Execute custom hooks by setting.
###############################################################################
def _execute_hooks(hooks, function_parameters=None, constructor_parameters=None):
    try:
        if hooks:
            hooks = [str(hook).strip() for hook in str(hooks).split(",")]
            context = {}

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

                context.update(
                    fn(
                        **(
                            function_parameters
                            if type(function_parameters) is dict
                            and len(function_parameters)
                            else {}
                        )
                    )
                    if callable(fn)
                    else {}
                )

                # spec = find_spec(str(module_name).strip())

                # if spec is None:
                #     continue

                # agent = import_module(str(module_name).strip())

                # if hasattr(agent, str(class_name).strip()):
                #     agent = getattr(agent, str(class_name).strip())()

                # if not hasattr(agent, str(function_name).strip()):
                #     continue

                # context.update(getattr(agent, str(function_name).strip())(authorizer))
            return context
        return None
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
            not role.permissions
            or not role.role_id
            or type(role.permissions) is not list
            or len(role.permissions) < 1
        ):
            continue

        permissions += role.permissions

    rules = []

    for permission in permissions:
        if (
            not permission.permissions
            or not permission.resource_id
            or type(permission.permissions) is not list
            or len(permission.permissions) < 1
        ):
            continue

        rules += permission.permissions

    m = {}
    request_operation = str(resource.get("operation", "")).strip().lower()
    request_operation_name = str(resource.get("operation_name", "")).strip().lower()
    request_fields = resource.get("fields")

    for rule in rules:
        if (
            not rule.operation
            or not rule.operation_name
            or request_operation != str(rule.operation).strip().lower()
        ):
            continue

        operation_name = str(rule.operation_name).strip().lower()

        if not m.get(operation_name):
            m[operation_name] = []

        if type(rule.exclude) is list and len(rule.exclude):
            m[operation_name] = list(set(m[operation_name] + rule.exclude))

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
def is_whitelisted(event):
    authorizer = event.get("requestContext", {}).get("authorizer", {})

    if type(authorizer.get("is_allowed_by_whitelist")) is bool:
        return authorizer.get("is_allowed_by_whitelist")

    return bool(int(str(authorizer.get("is_allowed_by_whitelist", 0)).strip()))


###############################################################################
# Permission verification response.
###############################################################################
def authorize_response(event, context):
    print("Authorize response context::::::::::::::::::", context, context.__dict__)
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    try:
        headers = dict(
            (key.strip().lower(), value)
            for key, value in event.get("headers", []).items()
        )
        principal = event.get("path", "/")
        api_id = event.get("requestContext", {}).get("apiId")
        method_arn_fragments = event.get("methodArn").split(":")
        api_gateway_arn_fragments = method_arn_fragments[5].split("/")
        region = method_arn_fragments[3]
        aws_account_id = method_arn_fragments[4]
        stage = api_gateway_arn_fragments[1]
        area = api_gateway_arn_fragments[3]
        # Use `endpoint_id` to differentiate app channels
        endpoint_id = api_gateway_arn_fragments[4]

        if endpoint_id is None:
            raise Exception("Unrecognized request origin", 401)

        authorizer = Authorizer(principal, aws_account_id, api_id, region, stage)
        setting_key = f"{stage}_{area}_{endpoint_id}"
        settings = dict(
            (item.variable, item.value)
            for item in ConfigDataModel.query(setting_key, None)
        )

        if len(settings.keys()) < 1:
            raise Exception(f"Missing required configuration(s) `{setting_key}`", 500)
        elif settings.get("user_source") is None:
            raise Exception(f"Missing configuration item `user_source`", 400)

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

        # 1. Verify source ip ############################################################
        if _verify_whitelist(event, context):
            ctx.update(
                {
                    "is_allowed_by_whitelist": SwitchStatus.YES.value,
                }
            )

            return authorizer.authorize(is_allow=True, context=ctx)

        # 2. Verify user token ############################################################
        if _is_authorize_required(event):
            claims = _verify_token(settings, event)

            if not claims:
                raise Exception("Invalid token", 400)

            # # @TODO: Use hooks instead
            # # @TODO: Start
            # is_admin = int(str(claims.get("is_admin", SwitchStatus.NO.value)).strip())

            # # Use `endpoint_id` to differentiate app channels
            # if (
            #     bool(is_admin) == False
            #     and str(endpoint_id).strip() == Channel.SS3.value
            # ):
            #     owner_id = claims.get("seller_id")
            #     teams = claims.get("teams")

            #     if not owner_id or not teams:
            #         raise Exception("Invalid token", 400)
            #     elif not ctx.get("seller_id") or not ctx.get("team_id"):
            #         raise Exception("Missing required parameter(s)", 400)
            #     elif str(owner_id).strip() != ctx.get("seller_id"):
            #         raise Exception("Access exceeded", 403)
            #     else:
            #         teams = dict(**Utility.json_loads(teams))

            #         if teams.get(ctx.get("team_id")) is None:
            #             raise Exception("Access exceeded", 403)

            #         claims.pop("teams")
            #         claims.update(teams.get(ctx.get("team_id")))
            # # @TODO: End
            if settings.get("after_token_parsed_hooks"):
                claims.update(
                    _execute_hooks(
                        hooks=str(authorizer.get("after_token_parsed_hooks")).strip(),
                        function_parameters={
                            "claims": claims,
                            "context": ctx,
                        },
                    )
                )

            claims.update(ctx)
            return authorizer.authorize(is_allow=True, context=claims)

        return authorizer.authorize(is_allow=True, context=ctx)
    except Exception as e:
        raise e


###############################################################################
# Verify resource permission
###############################################################################
def verify_permission(event, context):
    print("Verify permission context::::::::::::::::::", context, context.__dict__)
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    try:
        if not _is_authorize_required(event) or is_whitelisted(event):
            return event

        if (
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
        body = event.get("body")
        function_name = event.get("pathParameters", {}).get("proxy").strip()
        content_type = headers.get("content-type", "")
        area = event.get("pathParameters", {}).get("area")
        endpoint_id = event.get("pathParameters", {}).get("endpoint_id")
        is_admin = bool(int(str(authorizer.get("is_admin", 0)).strip()))
        uid = str(authorizer.get("user_id")).strip()  # uid = authorizer.get("sub")
        owner_id = str(authorizer.get("seller_id")).strip()
        group_id = str(authorizer.get("team_id")).strip()
        # method = event["httpMethod"]
        function_operations = function_config.get("config", {}).get("operations")
        module_name = function_config.get("config", {}).get("module_name")
        class_name = function_config.get("config", {}).get("class_name")
        message = f"Don't have the permission to access at /{area}/{endpoint_id}/{function_name}."

        if not function_operations or not module_name or not class_name or not uid:
            raise Exception(message, 403)

        if str(content_type).strip().lower() == "application/json":
            body_json = json.loads(body)

            if "query" in body_json:
                body = body_json["query"]

        # Parse the graphql request's body to AST and extract fields from the AST
        flatten_ast = Graphql.extract_flatten_ast(body)

        if type(flatten_ast) is not list or len(flatten_ast) < 1:
            raise Exception(message, 403)

        # Check user's permissions
        filter_conditions = RelationshipModel.user_id == uid

        if not is_admin and group_id:
            filter_conditions = (RelationshipModel.user_id == uid) & (
                RelationshipModel.group_id == group_id
            )

        role_ids = list(
            set(
                [
                    str(relationship.role_id).strip()
                    for relationship in RelationshipModel.scan(filter_conditions)
                ]
            )
        )
        print("Verify permission role ids::::::", role_ids)

        if len(role_ids) < 1:
            raise Exception(message, 403)

        roles = [role for role in RoleModel.scan(RoleModel.role_id.is_in(*role_ids))]

        if len(roles) < 1:
            raise Exception(message, 403)

        print("Verify permission roles::::::", roles, len(roles))

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

        # Attatch additional info to context
        additional_context = {
            "roles": [
                {
                    "role_id": str(role.role_id).strip(),
                    "name": str(role.name).strip(),
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
                )
            )

        event["requestContext"]["additionalContext"] = additional_context

        if type(context) is dict and len(context):
            event["requestContext"]["authorizer"].update(context)

        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~", event)
        return event
    except Exception as e:
        raise e


###############################################################################
# Get a list of resource permissions for a specified user
###############################################################################
def get_user_permissions(user_id, is_admin=0):
    try:
        if not user_id:
            return None

        user_id = str(user_id).strip()

        # Query user / group / role relationships
        role_ids = list(
            set(
                [
                    str(relationship.role_id).strip()
                    for relationship in RelationshipModel.scan(
                        RelationshipModel.user_id == user_id
                    )
                ]
            )
        )

        if len(role_ids) < 1:
            return None

        rules = []

        for role in RoleModel.scan(RoleModel.role_id.is_in(*role_ids)):
            rules += role.permissions

        resource_ids = list(set([str(rule.resource_id).strip() for rule in rules]))

        if len(resource_ids) < 1:
            return None

        resources = {}

        for resource in ResourceModel.scan(
            ResourceModel.resource_id.is_in(*resource_ids)
        ):
            resources[resource.resource_id] = resource

        result = {}

        for rule in rules:
            resource_id = str(rule.resource_id).strip()
            resource = resources.get(resource_id)

            if (
                not resource_id
                or not hasattr(resource, "function")
                or not hasattr(resource, "operations")
            ):
                continue

            function_name = getattr(resource, "function")

            if not result.get(function_name):
                result[function_name] = []

            if type(rule.permissions):
                for permission in rule.permissions:
                    if (
                        permission.operation
                        and permission.operation_name
                        and permission.operation != ""
                        and permission.operation_name != ""
                    ):
                        result[function_name].append(
                            str(permission.operation_name).strip().lower()
                        )

            result[function_name] = list(set(result[function_name]))

        return result
    except Exception as e:
        raise e


###############################################################################
# Check user permissions.
###############################################################################
def check_user_permissions(
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
        if (
            not module_name
            or not class_name
            or not function_name
            or not operation
            or not operation_type
            or not user_id
            or not group_id
            or relationship_type is None
        ):
            return False

        get_users = Utility.import_dynamically(
            "relation_engine",
            "get_users_by_cognito_user_id",
            "RelationEngine",
            {"logger": None},
        )

        if not callable(get_users):
            raise Exception("Module is not exists or the function is uncallable", 500)

        users = get_users([str(user_id).strip()])

        if len(users) < 1:
            return False
        elif bool(
            int(str(users.get(str(user_id).strip(), {}).get("is_admin", 0)).strip())
        ):
            return True

        ### 1. Check user & team relationship exists.
        filter_condition = (
            (RelationshipModel.user_id == str(user_id).strip())
            & (RelationshipModel.group_id == str(group_id).strip())
            & (RelationshipModel.type == int(relationship_type))
        )
        role_ids = list(
            set(
                [
                    relationship.role_id
                    for relationship in RelationshipModel.scan(
                        filter_condition=filter_condition
                    )
                    if relationship.role_id
                ]
            )
        )

        if len(role_ids) < 1:
            return False

        #### 1.1. Get roles by role ids
        # @TODO: len(role_ids) must less than 99
        max_length = 90
        permissions = []

        for i in range(0, len(role_ids), max_length):
            filter_condition = RoleModel.role_id.is_in(*role_ids[i : i + max_length])

            for role in RoleModel.scan(filter_condition=filter_condition):
                if (
                    role.permissions
                    and type(role.permissions) is list
                    and len(role.permissions)
                ):
                    permissions += role.permissions

        if len(permissions) < 1:
            return False

        ### 2. Get resources.
        filter_condition = (
            (ResourceModel.module_name == str(module_name).strip())
            & (ResourceModel.class_name == str(class_name).strip())
            & (ResourceModel.function == str(function_name).strip())
        )
        resource_ids = list(
            set(
                [
                    str(resource.resource_id).strip()
                    for resource in ResourceModel.scan(
                        filter_condition=filter_condition
                    )
                    if resource.resource_id
                ]
            )
        )

        if len(resource_ids) < 1:
            return False

        operation_type = str(operation_type).strip()
        operation = str(operation).strip()

        for permission in permissions:
            if (
                not permission.resource_id
                or type(permission.permissions) is not list
                or len(permission.permissions) < 1
            ):
                continue

            if str(permission.resource_id).strip() in resource_ids:
                for p in permission.permissions:
                    if p.operation == operation_type and p.operation_name == operation:
                        return True

        return False
    except Exception as e:
        raise e
