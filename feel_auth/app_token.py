"""
Token management
"""
from flask import current_app, request, abort
from itsdangerous import BadSignature
from itsdangerous import SignatureExpired
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer


class ApplicationToken():
    """
    Manage the application tokens
    """

    def __init__(self, application=None, object_id=None):
        self.application = application
        self.object_id = object_id

    @staticmethod
    def _deserialize(token: str, key: str):
        """
        Deserialize a token token to retrieve the data related

        Parameters
        ----------
        token: str
            The current application token used
        key: str
            The key to deserialize the token

        Returns
        -------
        data: dict
            The data dictionary with the application information
        """
        s = Serializer(key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        return data

    @staticmethod
    def get_apptoken(ApplicationModel, api_key: str):
        """
        Retrieve the app token, given the ApplicationModel, api_key and object_id

        Parameters
        ----------
        ApplicationModel: Any
            The db Model storing the api_key (it must contain an api_key string field)
        api_key: str
            The secret key from the application
        object_id: int
            The object id used to validate the permissions
            i.e: A partner must have permission to change only its own objects (videos, devices, etc)

        Returns
        -------
        str
            The short lived access token
        """
        if not ApplicationModel:
            abort(400, 'Undefined application model')
        application = ApplicationModel.query.filter_by(api_key=api_key).first()
        if not application:
            raise abort(400, 'Application not found')
        return ApplicationToken.generate_access_token_string(application)

    @staticmethod
    def generate_access_token_string(application, expiration=None):
        """
        Generate the short live access token, given the application and object id

        Parameters
        ----------
        application: The application requesting the token
        object_id: The id of the object asking permission for
        expiration: The expiration in seconds

        Returns
        -------
        str
            The short living access token
        """
        assert application.id is not None # Can happen if application object is not saved to DB yet

        if expiration is None:
            expiration = current_app.config.get('ACCESS_TOKEN_EXPIRATION', 60*60*24)

        options = {
            'id': application.id
        }
        s = Serializer(current_app.secret_key, expires_in=expiration)
        return s.dumps(options)

    @staticmethod
    def verify_and_deserialize(ApplicationModel, token: str, object_id, query_validation):
        """
        Verify the deserialized token, checking if it matches the validation parameters

        ApplicationModel: Any
            The model used for storing the api_key (it must contain an api_key string field)
        token: str
            The current application token used
        query_validation: Callable
            A callable object returning a boolean indicating whether the validation worked or not

        Returns
        -------
        bool
            Indicates whether the verification were successful or not
        """
        data = ApplicationToken._deserialize(token, current_app.secret_key)

        if data is None or 'id' not in data:
            return None # no application id in token

        application = ApplicationModel.query.get(data['id'])
        if not query_validation(application, object_id):
            return None

        return application

    @staticmethod
    def app_authorized(fn, ApplicationModel, query_validation, *args, **kwargs):
        """
        Validator to check whether the application is authorized or not
        If any validation fails, the function raises an Exception, otherwise it ends gracefully

        Parameters
        ----------
        fn: Callable
            The function to call when successful
        ApplicationModel: Any
            The model used for storing the api_key (it must contain an api_key string field)
        query_validation: Callable
            A callable object returning a boolean indicating whether the validation worked or not
        """
        access_token_req_var = current_app.config.get('ACCESS_TOKEN_REQ_VAR', 'apptoken')
        token = request.args.get(access_token_req_var)
        access_object_id_param = current_app.config.get('ACCESS_OBJECT_ID_PARAM', 'device_id')
        object_id = request.json and request.json.get(access_object_id_param) or request.args.get(access_object_id_param)

        if not token:
            return {'message': 'No {} in request url'.format(access_token_req_var)}, 401

        application = ApplicationToken.verify_and_deserialize(ApplicationModel, token, object_id, query_validation)
        if application is None:
            return {'message': 'Invalid {}'.format(access_token_req_var)}, 401

        kwargs['application'] = application
        return fn(*args, **kwargs)

