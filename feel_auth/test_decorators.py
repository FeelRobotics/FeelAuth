from functools import wraps
from .mocks import MockApplicationModel
from .app_token import ApplicationToken

def _app_authorized_valid_app(fn, model, *args, **kw):
    def query_validation(application, object_id):
        return True
    return ApplicationToken.app_authorized(fn, model, query_validation, *args, **kw)


def _app_authorized_invalid_app(fn, model, *args, **kw):
    def query_validation(application, object_id):
        return False
    return ApplicationToken.app_authorized(fn, model, query_validation, *args, **kw)


def app_authorized_valid_app(fn):
    @wraps(fn)
    def wrapped_func(*args, **kwargs):
        return _app_authorized_valid_app(fn, MockApplicationModel, *args, **kwargs)
    return wrapped_func

def app_authorized_invalid_app(fn):
    @wraps(fn)
    def wrapped_func(*args, **kwargs):
        return _app_authorized_invalid_app(fn, MockApplicationModel, *args, **kwargs)
    return wrapped_func
