class VaultProjectKeyringAuth(object):
    def login(self, client):
        self._login(client)
        assert client.is_authenticated()

    def _login(self, client):
        raise NotImplementedError


class VaultProjectKeyringAppRoleAuth(VaultProjectKeyringAuth):
    """
See https://hvac.readthedocs.io/en/stable/source/hvac_v1.html#hvac.v1.Client.auth_approle
    """
    def __init__(self, role_id, secret_id, **kwargs):
        self.role_id = role_id
        self.secret_id = secret_id
        self.kwargs = kwargs

    def _login(self, client):
        client.auth_approle(role_id=self.role_id, secret_id=self.secret_id, **self.kwargs)


class VaultProjectKeyringUserPasswordAuth(VaultProjectKeyringAuth):
    """
See https://hvac.readthedocs.io/en/stable/source/hvac_v1.html?highlight=auth_userpass#hvac.v1.Client.auth_userpass
    """
    def __init__(self, username, password, **kwargs):
        self.username = username
        self.password = password
        self.kwargs = kwargs

    def _login(self, client):
        client.auth_userpass(username=self.username, password=self.password, **self.kwargs)


class VaultProjectKeyringTokenAuth(VaultProjectKeyringAuth):
    def __init__(self, token):
        self.token = token

    def _login(self, client):
        client.token = self.token


class VaultProjectKeyringIAMAuth(VaultProjectKeyringAuth):
    """
See https://hvac.readthedocs.io/en/stable/source/hvac_v1.html#hvac.v1.Client.auth_aws_iam
    """
    def __init__(self, aws_access_key, aws_secret_key, **kwargs):
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.kwargs = kwargs

    def _login(self, client):
        client.auth_aws_iam(access_key=self.aws_access_key,
                            secret_key=self.aws_secret_key,
                            **self.kwargs
                            )


class VaultProjectKeyringEC2Auth(VaultProjectKeyringAuth):
    """
See https://hvac.readthedocs.io/en/stable/source/hvac_v1.html#hvac.v1.Client.auth_ec2
    """
    def __init__(self, pkcs7, **kwargs):
        self.pkcs7 = pkcs7
        self.kwargs = kwargs

    def _login(self, client):
        client.auth_ec2(pkcs7=self.pkcs7, **self.kwargs)


class VaultProjectKeyringAzureAuth(VaultProjectKeyringAuth):
    """
See https://hvac.readthedocs.io/en/stable/source/hvac_api_auth_methods.html#hvac.api.auth_methods.Azure.logind
    """
    def __init__(self, azure_role, **kwargs):
        self.azure_role = azure_role
        self.kwargs = kwargs

    def _login(self, client):
        client.azure.login(role=self.azure_role, **self.kwargs)


class VaultProjectKeyringGCPAuth(VaultProjectKeyringAuth):
    """
See https://hvac.readthedocs.io/en/stable/source/hvac_api_auth_methods.html#hvac.api.auth_methods.Gcp.login
    """
    def __init__(self, gcp_role, **kwargs):
        self.gcp_role = gcp_role
        self.kwargs = kwargs

    def _login(self, client):
        client.auth_kubernetes(role=self.gcp_role, **self.kwargs)


class VaultProjectKeyringKubernetesAuth(VaultProjectKeyringAuth):
    """
See https://hvac.readthedocs.io/en/stable/source/hvac_v1.html?highlight=auth_kubernetes#hvac.v1.Client.auth_kubernetes
    """
    def __init__(self, kub_role, kub_jwt, **kwargs):
        self.kub_role = kub_role
        self.kub_jwt = kub_jwt
        self.kwargs = kwargs

    def _login(self, client):
        client.auth_kubernetes(role=self.kub_role, jwt=self.kub_jwt, **self.kwargs)


class VaultProjectKeyringLDAPAuth(VaultProjectKeyringAuth):
    """
See https://hvac.readthedocs.io/en/stable/source/hvac_api_auth_methods.html#hvac.api.auth_methods.Ldap.login
    """
    def __init__(self, username, password, **kwargs):
        self.username = username
        self.password = password
        self.kwargs = kwargs

    def _login(self, client):
        client.auth.ldap.login(username=self.username, password=self.password, **self.kwargs)


class VaultProjectKeyringGitHubAuth(VaultProjectKeyringAuth):
    """
See https://hvac.readthedocs.io/en/stable/source/hvac_api_auth_methods.html#hvac.api.auth_methods.Github.login
    """
    def __init__(self, token, **kwargs):
        self.github_token = token
        self.kwargs = kwargs

    def _login(self, client):
        client.auth.github.login(token=self.github_token, **self.kwargs)


class VaultProjectKeyringMFAAuth(VaultProjectKeyringAuth):
    """
See https://hvac.readthedocs.io/en/stable/usage/auth_methods/mfa.html#authentication-login
    """
    def __init__(self, username, password, passcode, **kwargs):
        self.username = username
        self.password = password
        self.passcode = passcode
        self.kwargs = kwargs

    def _login(self, client):
        client.auth_userpass(username=self.username,
                                  password=self.password,
                                  passcode=self.passcode,
                                  **self.kwargs)


class VaultProjectKeyringOktaAuth(VaultProjectKeyringAuth):
    """
See https://hvac.readthedocs.io/en/stable/source/hvac_api_auth_methods.html#hvac.api.auth_methods.Okta.login
    """
    def __init__(self, username, password, **kwargs):
        self.username = username
        self.password = password
        self.kwargs = kwargs

    def _login(self, client):
        client.auth.okta.login(username=self.username, password=self.password, **self.kwargs)


class VaultProjectKeyringGenericAuth(VaultProjectKeyringAuth):
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def _login(self, client):
        client.login(**self.kwargs)
