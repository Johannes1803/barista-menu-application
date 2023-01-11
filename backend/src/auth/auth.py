import json
import typing
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen
import logging

AUTH0_DOMAIN = "barista-study.eu.auth0.com"
ALGORITHMS = ["RS256"]
API_AUDIENCE = "barista"


auth_logger = logging.getLogger("auth_logger")


class AuthError(Exception):
    """
    AuthError Exception
    A standardized way to communicate auth failure modes
    """

    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def get_token_auth_header() -> str:
    """
    Read the authorization token from the request header.

    :return: authorization token
    :raise: AuthError - if the request header is not present or malformed
    """
    # check for presence of authorization key in header
    if not request.headers.get("Authorization"):
        raise AuthError(
            error="Authorization key missing in request header.", status_code=401
        )

    # check properties of authorization header
    auth_header: str = request.headers.get("Authorization")
    auth_components: typing.List[typing.AnyStr] = auth_header.split(" ")
    if len(auth_components) != 2:
        raise AuthError(
            error="Invalid format of authorization header.", status_code=401
        )
    elif auth_components[0].lower() != "bearer":
        raise AuthError(error="Auth header should start with 'Bearer'", status_code=401)

    auth_token = auth_components[1]
    return auth_token


def check_permissions(permission: str, payload: dict) -> bool:
    """
    Return true if payload of decoded token contains the requested permission, else raise AuthError.

    :param permission: str in the form '<verb>:<resource>'
    :param payload: from decoded jwt token
    :return: true if checks passed
    :raise AuthError - if permissions section is missing from the payload or
        the requested permission string is not in the payload permissions array
    """
    auth_logger.debug("checking permissions")
    if "permissions" not in payload:
        raise AuthError(error="'permissions' not set in payload.", status_code=403)
    elif permission not in payload["permissions"]:
        raise AuthError(
            error="User not authorized for requested permission.", status_code=403
        )
    return True


"""
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
"""


def verify_decode_jwt(token: str) -> dict:
    """
    Verify and decode a jwt token.


    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    :param token: jwt token encoded
    :return: decoded payload of token
    :raise AuthError if claims are invalid
    :raise AuthError if signature expired
    :raise AuthError if header is malformed
    """
    jsonurl = urlopen(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if "kid" not in unverified_header:
        raise AuthError(
            {"code": "invalid_header", "description": "Authorization malformed."}, 401
        )

    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer="https://" + AUTH0_DOMAIN + "/",
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError(
                {"code": "token_expired", "description": "Token expired."}, 401
            )

        except jwt.JWTClaimsError:
            raise AuthError(
                {
                    "code": "invalid_claims",
                    "description": "Incorrect claims. Please, check the audience and issuer.",
                },
                401,
            )
        except Exception:
            raise AuthError(
                {
                    "code": "invalid_header",
                    "description": "Unable to parse authentication token.",
                },
                400,
            )
    raise AuthError(
        {
            "code": "invalid_header",
            "description": "Unable to find the appropriate key.",
        },
        400,
    )



"""
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
"""


def requires_auth(permission: str = ""):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(*args, **kwargs)

        return wrapper

    return requires_auth_decorator
