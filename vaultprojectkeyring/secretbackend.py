from datetime import datetime
import hvac

class VaultProjectKeyringSecretBackend(object):
    def __init__(self, client, backend, interval=None):
        self.client = client
        self.interval = interval
        self.backend = backend
        self.last_renewed = None
        self.logic_backend = None

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
        value = self._get_password(entry)
        return value

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


class VaultProjectKeyringKvV2Backend(VaultProjectKeyringSecretBackend):
    def __init__(self, client, backend, interval=None):
        super().__init__(client, backend, interval)
        self.logic_backend = self.client.secrets.kv.v2

    @staticmethod
    def get_path(entry):
        return "/".join(entry)

    def _get_password(self, entry):
        try:
            result = self.logic_backend.read_secret_version(self.get_path(entry), mount_point=self.backend)
            return result["data"]["data"] if result else None
        except hvac.exceptions.InvalidPath:
            return None

    def _set_password(self, entry, value):
        secrets = self._get_password(entry)
        secrets = secrets if secrets else {}
        secrets["password"] = value
        result = self.logic_backend.create_or_update_secret(self.get_path(entry),
                                                            mount_point=self.backend,
                                                            secret=secrets)

    def _delete_password(self, entry):
        secrets = self._get_password(entry)
        del secrets["password"]
        result = self.logic_backend.create_or_update_secret(self.get_path(entry),
                                                            mount_point=self.backend,
                                                            secret=secrets)


class VaultProjectKeyringKvV1Backend(VaultProjectKeyringSecretBackend):
    def __init__(self, client, backend, interval=None):
        super().__init__(client, backend, interval)
        self.logic_backend = self.client.secrets.kv.v1

    @staticmethod
    def get_path(entry):
        return "/".join(entry)

    def _get_password(self, entry):
        try:
            result = self.logic_backend.read_secret(path=self.get_path(entry), mount_point=self.backend)
            return result["data"] if result else None
        except hvac.exceptions.InvalidPath:
            return None

    def _set_password(self, entry, value):
        result = self.logic_backend.create_or_update_secret(path=self.get_path(entry),
                                                            mount_point=self.backend,
                                                            secret={"password":value})

    def _delete_password(self, entry):
        result = self.logic_backend.delete_secret(path=self.get_path(entry), mount_point=self.backend)


secret_backend_mapping = {
    "kv_v2": VaultProjectKeyringKvV2Backend,
    "kv_v1": VaultProjectKeyringKvV1Backend
}


def get_secret_backend(client, backend, interval=None):
    backends_list = client.sys.list_mounted_secrets_engines()
    secret_backend = next(iter([bck for key, bck in backends_list.items() if key == "{}/".format(backend)]), None)
    if secret_backend is None:
        raise ValueError("Unable to find {} Backend".format(backend))
    if "options" in secret_backend and "version" in secret_backend.get("options"):
        backend_type = "{}_v{}".format(secret_backend.get("type"), secret_backend.get("options").get("version"))
    backend_type = secret_backend_mapping.get(backend_type)
    if backend_type is None:
        raise ValueError("Backend type handler not found")
    return backend_type(client, backend, interval)
