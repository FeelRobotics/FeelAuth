from distutils.core import setup
from pip.req import parse_requirements

install_reqs = parse_requirements('requirements.txt', session='hack')

reqs = [str(ir.req) for ir in install_reqs]

setup(name='feel_auth',
    version='0.1',
    py_modules=['feel_auth'],
    install_reqs=reqs
)