from datetime import datetime
import hvac


class VaultProjectKeyringSecretBackend(object):
    def __init__(self, client, backend, secret_prefix=None, interval=None):
        self.client = client
        self.interval = interval
        self.backend = backend
        self.secret_prefix = secret_prefix
        self.last_renewed = None
        self.logic_backend = None

    def get_path(self, entry):
        if self.secret_prefix is not None:
            return "/".join([self.secret_prefix] + list(entry))
        return "/".join(entry)

    def renew_token(self):
        if self.interval is None:
            return
        if type(self.interval) is not int:
            raise TypeError("Interval value is not an int")
        try:
            if self.last_renewed is None or (datetime.now() - self.last_renewed).total_seconds() > self.interval:
                self.client.renew_token()
                self.last_renewed = datetime.now()
        except hvac.exceptions.InvalidRequest as e:
            raise RuntimeError("Reniew of Vault Token failed: {}".format(e))

    def get_password(self, entry):
        self.renew_token()
        return self._get_password(entry)

    def set_password(self, entry, value):
        self.renew_token()
        return self._set_password(entry, value)

    def delete_password(self, entry):
        self.renew_token()
        value = self._get_password(entry)
        if self._delete_password(entry):
            return value
        else:
            return False

    def _get_password(self, entry):
        raise NotImplementedError

    def _set_password(self, entry, value):
        raise NotImplementedError

    def _delete_password(self, entry):
        raise NotImplementedError


class VaultProjectKeyringKvV1Backend(VaultProjectKeyringSecretBackend):
    def __init__(self, client, backend, secret_prefix=None, interval=None):
        super().__init__(client, backend, secret_prefix, interval)
        self.logic_backend = self.client.secrets.kv.v1

    def _get_password(self, entry):
        try:
            result = self.logic_backend.read_secret(path=self.get_path(entry), mount_point=self.backend)
            return result["data"] if result else None
        except hvac.exceptions.InvalidPath:
            return None

    def _set_password(self, entry, value):
        return self.logic_backend.create_or_update_secret(path=self.get_path(entry),
                                                          mount_point=self.backend,
                                                          secret={"password": value})

    def _delete_password(self, entry):
        return self.logic_backend.delete_secret(path=self.get_path(entry),
                                                mount_point=self.backend)


class VaultProjectKeyringKvV2Backend(VaultProjectKeyringSecretBackend):
    def __init__(self, client, backend, secret_prefix=None, interval=None):
        super().__init__(client, backend, secret_prefix, interval)
        self.logic_backend = self.client.secrets.kv.v2

    def _get_password(self, entry):
        try:
            result = self.logic_backend.read_secret_version(self.get_path(entry),
                                                            mount_point=self.backend)
            return result["data"]["data"] if result else None
        except hvac.exceptions.InvalidPath:
            return None

    def _set_password(self, entry, value):
        secrets = self._get_password(entry)
        secrets = secrets if secrets else {}
        secrets["password"] = value
        return self.logic_backend.create_or_update_secret(self.get_path(entry),
                                                          mount_point=self.backend,
                                                          secret=secrets)

    def _delete_password(self, entry):
        secrets = self._get_password(entry)
        del secrets["password"]
        return self.logic_backend.create_or_update_secret(self.get_path(entry),
                                                          mount_point=self.backend,
                                                          secret=secrets)


secret_backend_mapping = {
    "kv_v1": VaultProjectKeyringKvV1Backend,
    "kv_v2": VaultProjectKeyringKvV2Backend
}


def get_secret_backend(client, backend, backend_type=None, secret_prefix=None, interval=None):
    if backend_type is None:
        if backend == "cubbyhole":
            backend_type = "kv_v1"
        else:
            backends_list = client.sys.list_mounted_secrets_engines()
            secret_backend = next(iter([bck for key, bck in backends_list.items() if key == "{}/".format(backend)]), None)
            if secret_backend is None:
                raise ValueError("Unable to find {} Backend".format(backend))
            if "options" in secret_backend and "version" in secret_backend.get("options", {}):
                backend_type = "{}_v{}".format(secret_backend.get("type"), secret_backend.get("options").get("version"))
    backend_impl = secret_backend_mapping.get(backend_type)
    if backend_impl is None:
        raise ValueError("Backend type handler not found")
    return backend_impl(client, backend, secret_prefix, interval)
