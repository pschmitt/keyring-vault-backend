#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function
import hvac
import keyring.backend
import logging
import os
import sys
from authbackend import VaultProjectKeyringTokenAuth
from authbackend import VaultProjectKeyringUserPasswordAuth
from secretbackend import get_secret_backend

# logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class VaultProjectKeyring(keyring.backend.KeyringBackend):
    '''
    Keyring backend backed by the vaultproject
    '''
    priority = 1

    def __init__(self, url=None, token=None, cert=None, verify=None,
                 timeout=None, proxies=None, vault_backend='keyring', interval=-1):
        self.url = url if url else os.environ.get(
            'VAULT_ADDR', 'http://localhost:8200'
        )
        self.auth_method = None
        self.secret_backend = None
        token = token if token else os.environ.get('VAULT_TOKEN', None)
        if verify is not None:
            self.verify = verify
        else:
            self.verify = 'VAULT_SKIP_VERIFY' not in os.environ
        self.cert = cert
        self.timeout = timeout
        self.proxies = proxies
        self.vault_backend = vault_backend
        self.client = None
        if token is not None:
            self.set_auth_method(VaultProjectKeyringTokenAuth(token))

    def set_auth_method(self, auth):
        self.auth_method = auth
        self.client = hvac.Client(
            self.url,
            cert=self.cert,
            verify=self.verify,
            timeout=self.timeout,
            proxies=self.proxies
        )
        self.auth_method.login(self.client)
        self.secret_backend = get_secret_backend(self.client, self.vault_backend)

    def set_password(self, servicename, username, password):
        try:
            response = self.secret_backend.set_password([servicename, username], password)
        except Exception as e:
            return keyring.errors.PasswordSetError(e.message)

    def get_password(self, servicename, username):
        response = self.secret_backend.get_password([servicename, username])
        if response:
            return response['password']

    def delete_password(self, servicename, username):
        try:
            response = self.secret_backend.delete_password([servicename, username])
            return response
        except Exception as e:
            return keyring.errors.PasswordDeleteError(e.message)


if __name__ == '__main__':
    sample_service = 'sample-service'
    sample_username = 'jynolen'
    sample_password = 'jynolen'

    # set the keyring for keyring lib
    vault = VaultProjectKeyring(vault_backend="keyring2")
    vault.set_auth_method(VaultProjectKeyringUserPasswordAuth(username=sample_username, password=sample_password))
    keyring.set_keyring(vault)

    try:
        keyring.set_password(sample_service, sample_username, sample_password+"____")
        print('Password stored sucessfully')
    except keyring.errors.PasswordSetError:
        print('Failed to store password', file=sys.stderr)

    assert keyring.get_password(sample_service, sample_username) \
           == sample_password+"____", 'Failed to retrieve password'

    try:
        keyring.delete_password(sample_service, sample_username)
        print('Password deleted sucessfully')
    except keyring.errors.PasswordSetError:
        print('Failed to delete password', file=sys.stderr)

    assert not keyring.get_password(sample_service, sample_username), \
        'get_password does NOT return None when the service is not known to vault'
