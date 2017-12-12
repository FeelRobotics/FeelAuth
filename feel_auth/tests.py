from flask import Flask
from flask_testing import TestCase
from functools import wraps
from flask_restful import Resource
from flask_restful import Api
from flask_restful import reqparse
from flask_restful import abort
from unittest.mock import patch

from itsdangerous import BadSignature
from itsdangerous import SignatureExpired

from .app_token import ApplicationToken
from .mocks import MockApplicationModel
from .test_decorators import app_authorized_valid_app
from .test_decorators import app_authorized_invalid_app

app = Flask(__name__, instance_relative_config=True)


def request_token(model):
    """
    Request token endpoint
    """
    parser = reqparse.RequestParser()
    parser.add_argument('api_key', type=str, help='{error_msg}. You must provide your api secret key', required=True, location='args')

    args = parser.parse_args()
    api_key = args.get('api_key')

    apptoken = ApplicationToken.get_apptoken(
        model,
        api_key=api_key
    )

    return {
        'apptoken': apptoken.decode('ascii')
    }


"""
Created Flask Restful Resources for testing purposes
"""
class TestAuthorizationValidResource(Resource):
    """
    Authorization valid app token
    """
    @app_authorized_valid_app
    def get(self, application):
        pass


class TestAuthorizationInvalidResource(Resource):
    """
    Authorization invalid app token
    """
    @app_authorized_invalid_app
    def get(self, application):
        pass


class TestTokenRequestNoneModel(Resource):
    """
    Token: No Application Model defined
    """
    def get(self):
        return request_token(None)


class TestTokenRequestOk(Resource):
    """
    Token: Ok
    """
    def get(self):
        return request_token(MockApplicationModel)


"""
Test API
"""
api = Api(app)

# Token request
api.add_resource(TestTokenRequestNoneModel, '/token_none_model')
api.add_resource(TestTokenRequestOk, '/token_ok')

# Authorization
api.add_resource(TestAuthorizationValidResource, '/url_valid')
api.add_resource(TestAuthorizationInvalidResource, '/url_invalid')


class AuthTestCase(TestCase):

    def create_app(self):
        self.client = app.test_client()
        app.secret_key = 'MYVERYSECRETKEY'
        return app

    def test_no_application_model_provided(self):
        response = self.client.get('/token_none_model?api_key=VALID')
        self.assert400(response)
        self.assertEqual(response.json['message'], 'Undefined application model')

    def test_application_not_found(self):
        response = self.client.get('/token_ok?api_key=INVALID')
        self.assert400(response)
        self.assertEqual(response.json['message'], 'Application not found')

    def test_missing_key(self):
        response = self.client.get('/token_ok')
        self.assert400(response)
        self.assertEqual(response.json['message']['api_key'], 'Missing required parameter in the query string. You must provide your api secret key')

    def test_token_success(self):
        response = self.client.get('/token_ok?api_key=VALID')
        self.assert200(response)
        self.assertIsNotNone(response.json['apptoken'])

    def test_no_permission_for_object(self):
        response = self.client.get('/token_ok?api_key=VALID')
        self.assert200(response)
        self.assertIsNotNone(response.json['apptoken'])

    @patch('feel_auth.app_token.ApplicationToken._deserialize', return_value={'id': 1})
    def test_permission_valid_for_object(self, deserialize):
        response = self.client.get('/url_valid?apptoken=VALID&device_id=1')
        self.assert200(response)

    @patch('feel_auth.app_token.ApplicationToken._deserialize', return_value=None)
    def test_invalid_token(self, deserialize):
        response = self.client.get('/url_valid?apptoken=VALID&device_id=1')
        self.assert401(response)
        self.assertEqual(response.json['message'], 'Invalid apptoken')
