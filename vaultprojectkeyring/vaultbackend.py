#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function
from datetime import datetime
from hvac.exceptions import InvalidRequest
import hvac
import keyring.backend
import logging
import os
import sys

# logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class VaultProjectKeyring(keyring.backend.KeyringBackend):
    '''
    Keyring backend backed by the vaultproject
    '''
    priority = 1

    def __init__(self, url=None, token=None, cert=None, verify=None,
                 timeout=None, proxies=None, vault_backend='keyring'):
        self.url = url if url else os.environ.get(
            'VAULT_ADDR', 'http://localhost:8200'
        )
        self.token = token if token else os.environ.get('VAULT_TOKEN', None)
        if verify is not None:
            self.verify = verify
        else:
            self.verify = 'VAULT_SKIP_VERIFY' not in os.environ
        self.cert = cert
        self.timeout = timeout
        self.proxies = proxies
        self.vault_backend = vault_backend

    def __get_client(self):
        return hvac.Client(
            self.url,
            token=self.token,
            cert=self.cert,
            verify=self.verify,
            timeout=self.timeout,
            proxies=self.proxies
        )

    def __get_path(self, servicename, username):
        if username:
            return '{}/{}/{}'.format(self.vault_backend, servicename, username)
        else:
            return '{}/{}'.format(self.vault_backend, servicename)

    def set_password(self, servicename, username, password):
        client = self.__get_client()
        try:
            client.write(
                self.__get_path(servicename, username),
                password=password
            )
        except Exception as e:
            return keyring.errors.PasswordSetError(e.message)

    def get_password(self, servicename, username):
        client = self.__get_client()
        response = client.read(self.__get_path(servicename, username))
        if response:
            return response['data']['password']

    def delete_password(self, servicename, username):
        client = self.__get_client()
        try:
            return client.delete(self.__get_path(servicename, username))
        except Exception as e:
            return keyring.errors.PasswordDeleteError(e.message)


class AutoRenewingTokenKeyring(VaultProjectKeyring):
    def __init__(self, interval=300, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.token is None:
            raise keyring.errors.InitError("You cannot use "
                                           "AutoRenewingTokenKeyring without "
                                           "an existing vault token")
        self.interval = interval
        self.last_renewed = None

    def _VaultProjectKeyring__get_client(self):
        client = hvac.Client(
            self.url,
            token=self.token,
            cert=self.cert,
            verify=self.verify,
            timeout=self.timeout,
            proxies=self.proxies
        )
        try:
            if self.last_renewed is None or \
                    (datetime.now() - self.last_renewed
                     ).total_seconds() > self.interval:
                client.renew_token()
                self.last_renewed = datetime.now()
        except InvalidRequest as e:
            logger.error("Vault token cannot be renewed: %s"
                         % e.args[0])
        return client


if __name__ == '__main__':
    sample_service = 'sample-service'
    sample_username = 'pschmitt'
    sample_password = 'fo0bar'

    # set the keyring for keyring lib
    keyring.set_keyring(VaultProjectKeyring())

    try:
        keyring.set_password(sample_service, sample_username, sample_password)
        print('Password stored sucessfully')
    except keyring.errors.PasswordSetError:
        print('Failed to store password', file=sys.stderr)

    assert keyring.get_password(sample_service, sample_username) \
           == sample_password, 'Failed to retrieve password'

    try:
        keyring.delete_password(sample_service, sample_username)
        print('Password deleted sucessfully')
    except keyring.errors.PasswordSetError:
        print('Failed to delete password', file=sys.stderr)

    assert not keyring.get_password(sample_service, sample_username), \
        'get_password does NOT return None when the service is not known to vault'
