#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from dotenv import load_dotenv
from os import path
import logging, sys, unittest, os

load_dotenv()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
sys.path.insert(0, path.dirname(path.dirname(path.dirname(path.realpath(__file__)))))

from silvaengine_authorizer import Authorizer

logger = logging.getLogger()
setting = {
    "region_name": os.getenv("REGION_NAME"),
    "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
    "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
    "app_client_id": os.getenv("APP_CLIENT_ID"),
    "app_client_secret": os.getenv("APP_CLIENT_SECRET"),
}

__author__ = "bl"


class SilvaEngineAuthorizerTest(unittest.TestCase):
    def setUp(self):
        self.instance = Authorizer(logger, **setting)
        logger.info("Initiate SilvaEngineAuthorizerTest ...")

    def tearDown(self):
        logger.info("Destory SilvaEngineAuthorizerTest ...")

    # @unittest.skip("demonstrating skipping")
    def test_authorize(self):
        request = {
            "type": "REQUEST",
            "methodArn": "arn:aws:execute-api:us-east-1:785238679596:3fizlvttp4/beta/POST/core/api/company_engine_graphql",
            "resource": "/{area}/{endpoint_id}/{proxy+}",
            "path": "/core/api/company_engine_graphql",
            "httpMethod": "ANY",
            "headers": {
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Authorization": "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI0OTc4MDU2Ny0yMjA4LTQ5MjItOGMxMi1iMjgzZTY5NTQzYzYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwic192ZW5kb3JfaWQiOiJTMTA3NjMiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9HTXZVaGF4UnMiLCJjb2duaXRvOnVzZXJuYW1lIjoiZWR3YXJkQG1hZ2lueC5jb20iLCJpc19hZG1pbiI6IjAiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiIwZWE0MTA4MS1hNDNiLTQyNWUtYjkzOC02NDViZTcwYzk4NDAiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTYyODcyOTY5MSwiZXhwIjoxNjI4ODAxNjkxLCJpYXQiOjE2Mjg3Mjk2OTEsInNlbGxlcl9pZCI6IjIwMTgiLCJlbWFpbCI6ImVkd2FyZEBtYWdpbnguY29tIn0.r4eJS_v4cfRijgMlZ72wvjqOFX3iNTYRTxHcqDReEQpY3kQcHybQI1e4k0S2Zk784b1C82D0fnMOr0Tsl_tctdLVZCyt17sjtgiBGZldNkBBBbKrF6ChJQzOFwscfu6BfeyqDLSk_bShDh8_45ili2aKZ0TE95ASGBoc2gPu9XqhqzC2b3ZpoA2m9iHJMdIij0l9VsYoSYKHb59KAA9eonfFhIJHmuVfskD_OGXcsiYMIzMxDeg0vfhO97gBQVSytkne-OhDfu6iREKAeGII2E7hQ4Nc4cq6MkviHBaF_AAtVgHMAb22DHchKnsJf9zE5qsgPuwcgk907FrL7arCcg",
                "CloudFront-Forwarded-Proto": "https",
                "CloudFront-Is-Desktop-Viewer": "true",
                "CloudFront-Is-Mobile-Viewer": "false",
                "CloudFront-Is-SmartTV-Viewer": "false",
                "CloudFront-Is-Tablet-Viewer": "false",
                "CloudFront-Viewer-Country": "CN",
                "Content-Length": "2944",
                "content-type": "application/json",
                "Host": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "origin": "http://localhost:3000",
                "Referer": "http://localhost:3000/",
                "sec-ch-ua": '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
                "sec-ch-ua-mobile": "?0",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
                "seller_id": "2018",
                "team_id": "357",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
                "Via": "2.0 feda34dcbf6a00e232656b7983c2c7f0.cloudfront.net (CloudFront)",
                "X-Amz-Cf-Id": "s9x8PP20Kle9SssxG70yk9hag6GZjNkycKyNL6jSN3UVJyAoJT9dUA==",
                "X-Amzn-Trace-Id": "Root=1-6114dc3f-19c01adf1f4423e86881251a",
                "x-api-key": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                "X-Forwarded-For": "220.191.46.189, 130.176.132.189",
                "X-Forwarded-Port": "443",
                "X-Forwarded-Proto": "https",
            },
            "multiValueHeaders": {
                "Accept": ["application/json, text/plain, */*"],
                "Accept-Encoding": ["gzip, deflate, br"],
                "Accept-Language": ["zh-CN,zh;q=0.9"],
                "Authorization": [
                    "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI0OTc4MDU2Ny0yMjA4LTQ5MjItOGMxMi1iMjgzZTY5NTQzYzYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwic192ZW5kb3JfaWQiOiJTMTA3NjMiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9HTXZVaGF4UnMiLCJjb2duaXRvOnVzZXJuYW1lIjoiZWR3YXJkQG1hZ2lueC5jb20iLCJpc19hZG1pbiI6IjAiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiIwZWE0MTA4MS1hNDNiLTQyNWUtYjkzOC02NDViZTcwYzk4NDAiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTYyODcyOTY5MSwiZXhwIjoxNjI4ODAxNjkxLCJpYXQiOjE2Mjg3Mjk2OTEsInNlbGxlcl9pZCI6IjIwMTgiLCJlbWFpbCI6ImVkd2FyZEBtYWdpbnguY29tIn0.r4eJS_v4cfRijgMlZ72wvjqOFX3iNTYRTxHcqDReEQpY3kQcHybQI1e4k0S2Zk784b1C82D0fnMOr0Tsl_tctdLVZCyt17sjtgiBGZldNkBBBbKrF6ChJQzOFwscfu6BfeyqDLSk_bShDh8_45ili2aKZ0TE95ASGBoc2gPu9XqhqzC2b3ZpoA2m9iHJMdIij0l9VsYoSYKHb59KAA9eonfFhIJHmuVfskD_OGXcsiYMIzMxDeg0vfhO97gBQVSytkne-OhDfu6iREKAeGII2E7hQ4Nc4cq6MkviHBaF_AAtVgHMAb22DHchKnsJf9zE5qsgPuwcgk907FrL7arCcg"
                ],
                "CloudFront-Forwarded-Proto": ["https"],
                "CloudFront-Is-Desktop-Viewer": ["true"],
                "CloudFront-Is-Mobile-Viewer": ["false"],
                "CloudFront-Is-SmartTV-Viewer": ["false"],
                "CloudFront-Is-Tablet-Viewer": ["false"],
                "CloudFront-Viewer-Country": ["CN"],
                "Content-Length": ["2944"],
                "content-type": ["application/json"],
                "Host": ["3fizlvttp4.execute-api.us-east-1.amazonaws.com"],
                "origin": ["http://localhost:3000"],
                "Referer": ["http://localhost:3000/"],
                "sec-ch-ua": [
                    '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"'
                ],
                "sec-ch-ua-mobile": ["?0"],
                "sec-fetch-dest": ["empty"],
                "sec-fetch-mode": ["cors"],
                "sec-fetch-site": ["cross-site"],
                "seller_id": ["2018"],
                "team_id": ["357"],
                "User-Agent": [
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"
                ],
                "Via": [
                    "2.0 feda34dcbf6a00e232656b7983c2c7f0.cloudfront.net (CloudFront)"
                ],
                "X-Amz-Cf-Id": [
                    "s9x8PP20Kle9SssxG70yk9hag6GZjNkycKyNL6jSN3UVJyAoJT9dUA=="
                ],
                "X-Amzn-Trace-Id": ["Root=1-6114dc3f-19c01adf1f4423e86881251a"],
                "x-api-key": ["dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4"],
                "X-Forwarded-For": ["220.191.46.189, 130.176.132.189"],
                "X-Forwarded-Port": ["443"],
                "X-Forwarded-Proto": ["https"],
            },
            "queryStringParameters": {},
            "multiValueQueryStringParameters": {},
            "pathParameters": {
                "area": "core",
                "proxy": "company_engine_graphql",
                "endpoint_id": "api",
            },
            "stageVariables": {},
            "requestContext": {
                "resourceId": "d5y1px",
                "resourcePath": "/{area}/{endpoint_id}/{proxy+}",
                "httpMethod": "POST",
                "extendedRequestId": "D8daBGpQoAMFwXg=",
                "requestTime": "12/Aug/2021:08:30:55 +0000",
                "path": "/beta/core/api/company_engine_graphql",
                "accountId": "785238679596",
                "protocol": "HTTP/1.1",
                "stage": "beta",
                "domainPrefix": "3fizlvttp4",
                "requestTimeEpoch": 1628757055955,
                "requestId": "d925a6f0-e7d9-414f-acbe-31f4c379bd07",
                "identity": {
                    "cognitoIdentityPoolId": None,
                    "cognitoIdentityId": None,
                    "apiKey": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                    "principalOrgId": None,
                    "cognitoAuthenticationType": None,
                    "userArn": None,
                    "apiKeyId": "faqkldfbx7",
                    "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
                    "accountId": None,
                    "caller": None,
                    "sourceIp": "220.191.46.189",
                    "accessKey": None,
                    "cognitoAuthenticationProvider": None,
                    "user": None,
                },
                "domainName": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "apiId": "3fizlvttp4",
            },
            "fnConfigurations": {
                "area": "core",
                "aws_lambda_arn": "arn:aws:lambda:us-east-1:785238679596:function:silvaengine_microcore",
                "config": {
                    "auth_required": False,
                    "class_name": "CompanyEngine",
                    "funct_type": "RequestResponse",
                    "graphql": False,
                    "methods": ["GET", "POST"],
                    "module_name": "company_engine",
                    "setting": "seller_engine_graphql",
                },
                "function": "company_engine_graphql",
            },
        }

        response = self.instance.authorize(request, None)

        print("test_authorize: ", response)
        print("#################################################")

    # @unittest.skip("demonstrating skipping")
    def test_verify_permissions(self):
        request = {
            "resource": "/{area}/{endpoint_id}/{proxy+}",
            "path": "/core/api/data_engine_graphql",
            "httpMethod": "POST",
            "headers": {
                "Accept": "application/json",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "zh-CN",
                "Authorization": "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI3MWMzNTU5Yi01ZWYxLTRiMGEtOGI1MS05YjQzOWE1N2ZmYmYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfR012VWhheFJzIiwiY29nbml0bzp1c2VybmFtZSI6ImpuZ0BpbmdyZWRpZW50c29ubGluZS5jb20iLCJpc19hZG1pbiI6IjEiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiJlYTVkODEzMy01NTQyLTQ4NGYtOTBiMy1iZTg5NTZlZjUyODQiLCJ1c2VyX2lkIjoiMTE4IiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE2Mjk4MjA2MDcsImV4cCI6MTYyOTg5MjYwNywiaWF0IjoxNjI5ODIwNjA3LCJlbWFpbCI6ImpuZ0BpbmdyZWRpZW50c29ubGluZS5jb20ifQ.RLQaFgLc3KbEXHMocNj5TGKpPVihJH8ZYRlDgnqi_6IY-eNTqjDAV5YXW-4LRVSP4zDrkUxENNcfcda-iguPRPcHOcIlyQKzcI0n8Cxu2aUfIwOSbiG0UjGgaa73SJpUqmwUsEq_BENG1oyuKiYr0fQc58Z5Wb9sFZNCA1HlE6uqohGb6LOfgrOKXytpuxAgWg2321gMPB1aTrTsFeYpOPce4lv7reBu_PPUr7OBS3DH63RL-S393E9Y2O4anCaAdrn10Tq_j7uLfpLtgTX7JyQO4FRugvxK7bPlkEbNeeS0sauerGHlJ5EXY8XLsx4duIKFD4fLArm8-6vrUW_Q_w",
                "CloudFront-Forwarded-Proto": "https",
                "CloudFront-Is-Desktop-Viewer": "true",
                "CloudFront-Is-Mobile-Viewer": "false",
                "CloudFront-Is-SmartTV-Viewer": "false",
                "CloudFront-Is-Tablet-Viewer": "false",
                "CloudFront-Viewer-Country": "HK",
                "content-type": "application/json",
                "Host": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "origin": "electron://altair",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AltairGraphQLClient/4.0.9 Chrome/89.0.4389.82 Electron/12.0.1 Safari/537.36",
                "Via": "2.0 da2930182b81a0969bededaf2726cadc.cloudfront.net (CloudFront)",
                "X-Amz-Cf-Id": "A3z-Ef_o89je2FfMudkio2PP2X2NheRSFVwU0kMoQ8hDluzpg3NocQ==",
                "X-Amzn-Trace-Id": "Root=1-61258e7f-600f8e344c290daa06acb931",
                "x-api-key": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                "X-Forwarded-For": "103.97.201.121, 130.176.93.156",
                "X-Forwarded-Port": "443",
                "X-Forwarded-Proto": "https",
            },
            "multiValueHeaders": {
                "Accept": ["application/json"],
                "Accept-Encoding": ["gzip, deflate, br"],
                "Accept-Language": ["zh-CN"],
                "Authorization": [
                    "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI3MWMzNTU5Yi01ZWYxLTRiMGEtOGI1MS05YjQzOWE1N2ZmYmYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfR012VWhheFJzIiwiY29nbml0bzp1c2VybmFtZSI6ImpuZ0BpbmdyZWRpZW50c29ubGluZS5jb20iLCJpc19hZG1pbiI6IjEiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiJlYTVkODEzMy01NTQyLTQ4NGYtOTBiMy1iZTg5NTZlZjUyODQiLCJ1c2VyX2lkIjoiMTE4IiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE2Mjk4MjA2MDcsImV4cCI6MTYyOTg5MjYwNywiaWF0IjoxNjI5ODIwNjA3LCJlbWFpbCI6ImpuZ0BpbmdyZWRpZW50c29ubGluZS5jb20ifQ.RLQaFgLc3KbEXHMocNj5TGKpPVihJH8ZYRlDgnqi_6IY-eNTqjDAV5YXW-4LRVSP4zDrkUxENNcfcda-iguPRPcHOcIlyQKzcI0n8Cxu2aUfIwOSbiG0UjGgaa73SJpUqmwUsEq_BENG1oyuKiYr0fQc58Z5Wb9sFZNCA1HlE6uqohGb6LOfgrOKXytpuxAgWg2321gMPB1aTrTsFeYpOPce4lv7reBu_PPUr7OBS3DH63RL-S393E9Y2O4anCaAdrn10Tq_j7uLfpLtgTX7JyQO4FRugvxK7bPlkEbNeeS0sauerGHlJ5EXY8XLsx4duIKFD4fLArm8-6vrUW_Q_w"
                ],
                "CloudFront-Forwarded-Proto": ["https"],
                "CloudFront-Is-Desktop-Viewer": ["true"],
                "CloudFront-Is-Mobile-Viewer": ["false"],
                "CloudFront-Is-SmartTV-Viewer": ["false"],
                "CloudFront-Is-Tablet-Viewer": ["false"],
                "CloudFront-Viewer-Country": ["HK"],
                "content-type": ["application/json"],
                "Host": ["3fizlvttp4.execute-api.us-east-1.amazonaws.com"],
                "origin": ["electron://altair"],
                "sec-fetch-dest": ["empty"],
                "sec-fetch-mode": ["cors"],
                "sec-fetch-site": ["cross-site"],
                "User-Agent": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AltairGraphQLClient/4.0.9 Chrome/89.0.4389.82 Electron/12.0.1 Safari/537.36"
                ],
                "Via": [
                    "2.0 da2930182b81a0969bededaf2726cadc.cloudfront.net (CloudFront)"
                ],
                "X-Amz-Cf-Id": [
                    "A3z-Ef_o89je2FfMudkio2PP2X2NheRSFVwU0kMoQ8hDluzpg3NocQ=="
                ],
                "X-Amzn-Trace-Id": ["Root=1-61258e7f-600f8e344c290daa06acb931"],
                "x-api-key": ["dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4"],
                "X-Forwarded-For": ["103.97.201.121, 130.176.93.156"],
                "X-Forwarded-Port": ["443"],
                "X-Forwarded-Proto": ["https"],
            },
            "queryStringParameters": None,
            "multiValueQueryStringParameters": None,
            "pathParameters": {
                "area": "core",
                "proxy": "data_engine_graphql",
                "endpoint_id": "api",
            },
            "stageVariables": None,
            "requestContext": {
                "resourceId": "d5y1px",
                "authorizer": {
                    "sub": "71c3559b-5ef1-4b0a-8b51-9b439a57ffbf",
                    "email_verified": "true",
                    "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_GMvUhaxRs",
                    "principalId": "/core/api/data_engine_graphql",
                    "cognito:username": "jng@ingredientsonline.com",
                    "integrationLatency": 5037,
                    "is_admin": "1",
                    "aud": "et3i1tpbbmb41eogrdlp5qcsj",
                    "event_id": "ea5d8133-5542-484f-90b3-be8956ef5284",
                    "user_id": "118",
                    "token_use": "id",
                    "auth_time": "1629820607",
                    "exp": "1629892607",
                    "iat": "1629820607",
                    "email": "jng@ingredientsonline.com",
                },
                "resourcePath": "/{area}/{endpoint_id}/{proxy+}",
                "httpMethod": "POST",
                "extendedRequestId": "EmMz8FiOIAMFmhA=",
                "requestTime": "25/Aug/2021:00:27:43 +0000",
                "path": "/beta/core/api/data_engine_graphql",
                "accountId": "785238679596",
                "protocol": "HTTP/1.1",
                "stage": "beta",
                "domainPrefix": "3fizlvttp4",
                "requestTimeEpoch": 1629851263492,
                "requestId": "5e6a27e8-83a1-4a00-96aa-5cf23794b267",
                "identity": {
                    "cognitoIdentityPoolId": None,
                    "cognitoIdentityId": None,
                    "apiKey": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                    "principalOrgId": None,
                    "cognitoAuthenticationType": None,
                    "userArn": None,
                    "apiKeyId": "faqkldfbx7",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AltairGraphQLClient/4.0.9 Chrome/89.0.4389.82 Electron/12.0.1 Safari/537.36",
                    "accountId": None,
                    "caller": None,
                    "sourceIp": "103.97.201.121",
                    "accessKey": None,
                    "cognitoAuthenticationProvider": None,
                    "user": None,
                },
                "domainName": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "apiId": "3fizlvttp4",
            },
            "body": '{"query":"query {\\n  dataCenter {\\n    countries {\\n      lookupId\\n      lookupName\\n      lookupCode\\n      sortOrder\\n      custom1\\n      custom2\\n      custom3\\n    }\\n    freightTerms {\\n      lookupId\\n      lookupName\\n    }\\n    declineReasons {\\n      lookupId\\n      lookupName\\n    }\\n    paymentTypes {\\n      lookupId\\n      lookupName\\n    }\\n    paymentCycles {\\n      key\\n      value\\n    }\\n    documents {\\n      edges {\\n        node {\\n          docTypeGroupId\\n          docTypeGroup\\n          documentTypes {\\n            edges {\\n              node {\\n                docTypeId\\n                typeName\\n                requiredFlag\\n                sortOrder\\n                forQc\\n                forProduct\\n                forFactory\\n                forShipment\\n                uploadOnlyFlag\\n                docPrefix\\n                expireFlag\\n                docTypeGroupId\\n              }\\n            }\\n          }\\n        }\\n      }\\n    }\\n  }\\n}","variables":{},"operationName":null}',
            "isBase64Encoded": False,
            "fnConfigurations": {
                "area": "core",
                "aws_lambda_arn": "arn:aws:lambda:us-east-1:785238679596:function:silvaengine_microcore",
                "config": {
                    "auth_required": True,
                    "class_name": "DataEngine",
                    "funct_type": "RequestResponse",
                    "graphql": True,
                    "methods": ["POST"],
                    "module_name": "data_engine",
                    "operations": {"mutation": [], "query": ["dataCenter"]},
                    "setting": "product_engine_graphql",
                },
                "function": "data_engine_graphql",
            },
        }
        context = {
            "seller_id": 2018,
            "team_id": 357,
        }
        response = self.instance.verify_permission(request, context)

        print("test_verify_permissions: ", response)
        print("#################################################")


if __name__ == "__main__":
    unittest.main()
