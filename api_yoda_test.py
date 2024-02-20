import json
import re

import pytest
import requests
import urllib3
from pytest_bdd import (
    given,
    parsers,
    then,
    when,
)

portal_url = ""
api_url = ""
configuration = {}
roles = {}
user_cookies = {}

datarequest = False
deposit = False
intake = False
archive = False
smoke = False
skip_api = False
skip_ui = False
run_all = False
verbose_test = True




def login(user, password):
    """Login portal and retrieve CSRF and session cookies."""
    # Disable unsecure connection warning.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


    url = "https://its.yoda.uu.nl/user/login".format(portal_url)
    if verbose_test:
        print("Login for user {} (retrieve CSRF token) ...".format(user))


    client = requests.session()


    # Retrieve the login CSRF token.
    content = client.get(url, verify=False).content.decode()
    p = re.compile("tokenValue: '([a-zA-Z0-9._-]*)'")
    csrf = p.findall(content)[0]


    # Login as user.
    if verbose_test:
        print("Login for user {} (main login) ...".format(user))
    login_data = dict(csrf_token=csrf, username=user, password=password, next='/')
    response = client.post(url, data=login_data, headers=dict(Referer=url), verify=False)
    session = client.cookies['__Host-session']
    client.close()


    # Retrieve the authenticated CSRF token.
    content = response.content.decode()
    p = re.compile("tokenValue: '([a-zA-Z0-9._-]*)'")
    csrf = p.findall(content)[0]


    # Return CSRF and session cookies.
    if verbose_test:
        print("Login for user {} completed.".format(user))
    return csrf, session

password = 'Test'
a, b = login('grote004', password)
print (a, b)

