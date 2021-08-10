#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function

from functools import lru_cache
from keyring.backend import KeyringBackend
from keyring.errors import ExceptionRaisedContext
from keyring.util import properties
from os import environ
from sys import stderr

try:
    import hvac
except ImportError:
    pass

import logging

from .secretbackend import get_secret_backend

# logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class VaultProjectKeyring(KeyringBackend):
    '''
    Keyring backend backed by the vaultproject
    '''

    def __init__(self, url=None, token=None, cert=None, verify=None, interval=None,
                 timeout=None, proxies=None,
                 vault_backend='keyring', backend_type=None, secret_prefix=None):

        self.url = url if url else environ.get('VAULT_ADDR', 'http://localhost:8200')
        self.token = token if token else environ.get('VAULT_TOKEN', None)

        if verify is not None:
            self.verify = verify
        else:
            self.verify = 'VAULT_SKIP_VERIFY' not in environ

        self.cert = cert
        self.timeout = timeout
        self.proxies = proxies

        self.vault_backend = vault_backend
        self.backend_type = backend_type
        self.secret_prefix = secret_prefix
        self.interval = interval

        # don't initialise client/secret_backend here as __init__ is called during backend discovery

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        if not cls._has_hvac():
            raise RuntimeError("Requires hvac")
        if "KEYRING_VAULT_BACKEND" in environ:
            return 6
        return 1

    @classmethod
    def _has_hvac(cls):
        with ExceptionRaisedContext() as exc:
            hvac.__name__
        return not bool(exc)

    @property
    @lru_cache(maxsize=None)
    def client(self):
        return hvac.Client(
            self.url,
            token=self.token,
            cert=self.cert,
            verify=self.verify,
            timeout=self.timeout,
            proxies=self.proxies
        )

    @property
    @lru_cache(maxsize=None)
    def secret_backend(self):
        return get_secret_backend(self.client, self.vault_backend, self.backend_type, self.secret_prefix, self.interval)

    def get_password(self, servicename, username):
        response = self.secret_backend.get_password((servicename, username))
        if response:
            return response['password']

    def set_password(self, servicename, username, password):
        try:
            return self.secret_backend.set_password((servicename, username), password)
        except Exception as e:
            return keyring.errors.PasswordSetError(e.message)

    def delete_password(self, servicename, username):
        try:
            return self.secret_backend.delete_password((servicename, username))
        except Exception as e:
            return keyring.errors.PasswordDeleteError(e.message)


if __name__ == '__main__':
    import keyring

    test_service = 'test-service'
    test_username = 'test-user'
    test_password = 'test-P4$$w0rd!'

    # set the keyring for keyring lib
    keyring.set_keyring(VaultProjectKeyring(vault_backend='cubbyhole'))
    # keyring.set_keyring(VaultProjectKeyring(vault_backend='keyring1'))
    # keyring.set_keyring(VaultProjectKeyring(vault_backend='keyring2'))

    try:
        keyring.set_password(test_service, test_username, test_password)
        print('Password stored sucessfully')
    except keyring.errors.PasswordSetError:
        print('Failed to store password', file=stderr)

    assert keyring.get_password(test_service, test_username) \
        == test_password, 'Failed to retrieve password'

    try:
        keyring.delete_password(test_service, test_username)
        print('Password deleted sucessfully')
    except keyring.errors.PasswordSetError:
        print('Failed to delete password', file=stderr)

    assert not keyring.get_password(test_service, test_username), \
        'get_password does NOT return None when the service is not known to vault'
