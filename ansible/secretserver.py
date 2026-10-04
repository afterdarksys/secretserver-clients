# -*- coding: utf-8 -*-
# (c) AfterDark Technologies
# GNU General Public License v3.0+

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
    name: secretserver
    author: AfterDark Technologies (@afterdarksys)
    version_added: "1.0.0"
    short_description: Retrieve secrets from SecretServer.io
    description:
      - Fetches secret values from SecretServer.io using the path-based API.
      - Supports retrieval by container/key path or by secret name.
      - Supports historical versions (1=current, 2=previous, etc.).
    requirements:
      - urllib (standard library — no extra deps required)
    options:
      _terms:
        description: >
          Secret path(s) to retrieve. Format: C(container/key) or C(container/key/version).
          A bare name (no slash) is treated as a direct name lookup.
        required: true
        type: list
        elements: str
      api_url:
        description: >
          SecretServer API base URL. Must use https; plain http is accepted only
          for localhost, 127.0.0.1 or ::1. URLs containing credentials are rejected.
          Defaults to https://api.secretserver.io, or with O(use_cli_login) to
          the URL the C(ss) CLI is logged in to.
        env:
          - name: SS_API_URL
        ini:
          - section: secretserver
            key: api_url
        type: str
      api_key:
        description: >
          SecretServer API key. Required unless O(use_cli_login) is set;
          mutually exclusive with it.
        env:
          - name: SS_API_KEY
        ini:
          - section: secretserver
            key: api_key
        type: str
      use_cli_login:
        description: >
          Authenticate with the controller user's C(ss login) SSO session instead
          of an API key. Runs C(ss auth print-access-token --format json) (the
          binary from E(SS_CLI_PATH), else C(ss) on PATH) once per lookup, without
          a shell, with a 30 s timeout. Requires the C(secretserver) Python
          package 1.4.0 or newer on the controller. If the CLI is not logged in
          the lookup fails and asks you to run C(ss login).
        type: bool
        default: false
        version_added: "1.4.0"
      ca_path:
        description: >
          PEM CA bundle used to verify the server certificate, for deployments
          behind a private CA. It is added to the system trust store, so public
          CAs remain trusted. TLS verification cannot be disabled.
        env:
          - name: SS_CA_PATH
        ini:
          - section: secretserver
            key: ca_path
        type: path
      render:
        description: Resolve the term as a %%NAME%% template instead of a secret path.
        type: bool
        default: false
      timeout:
        description: HTTP request timeout in seconds.
        default: 10
        type: int
      version:
        description: >
          Secret version to retrieve (1=current, 2=previous).
          Overrides a version specified in the path term.
        type: int
    notes:
      - Use no_log=true on every task consuming secrets. Lookup results are not automatically redacted.
      - Store the api_key in Ansible Vault, not in plaintext, or use O(use_cli_login).
    seealso:
      - name: SecretServer API documentation
        link: https://secretserver.io/docs/api
        description: REST API inventory.
    extends_documentation_fragment: []
"""

EXAMPLES = r"""
- name: Read a secret without logging its value
  ansible.builtin.set_fact:
    database_password: "{{ lookup('afterdark.secretserver.secretserver', 'prod/database-password', api_key=vault_ss_key) }}"
  no_log: true

- name: Read a secret with your `ss login` session (no API key)
  ansible.builtin.set_fact:
    database_password: "{{ lookup('afterdark.secretserver.secretserver', 'prod/database-password', use_cli_login=true) }}"
  no_log: true
"""

RETURN = r"""
_raw:
  description: Secret value(s) retrieved from SecretServer.
  type: list
  elements: str
"""

import json
import ssl

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler, getproxies_environment
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
DEFAULT_API_URL = "https://api.secretserver.io"
LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")

display = Display()


class LookupModule(LookupBase):
    """SecretServer lookup plugin — retrieves secrets from SecretServer.io."""

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        api_key = self.get_option("api_key")
        api_url = self.get_option("api_url")
        if self.get_option("use_cli_login"):
            if api_key:
                raise AnsibleError("api_key and use_cli_login are mutually exclusive (check SS_API_KEY)")
            api_key, cli_api_url = cli_login_token()
            if api_url and cli_api_url and not same_api_origin(api_url, cli_api_url):
                raise AnsibleError(
                    "SecretServer api_url {} does not match the `ss login` session for {}".format(api_url, cli_api_url)
                )
            api_url = api_url or cli_api_url
        api_url = validate_api_url(api_url or DEFAULT_API_URL)
        self._ssl_context = make_ssl_context(self.get_option("ca_path"))
        timeout = int(self.get_option("timeout"))
        version_override = self.get_option("version")
        if timeout <= 0:
            raise AnsibleError("timeout must be positive")
        if version_override is not None and not 1 <= int(version_override) <= 12:
            raise AnsibleError("version must be between 1 and 12")

        if not api_key:
            raise AnsibleError(
                "SecretServer API key is required. "
                "Set SS_API_KEY env var or secretserver.api_key in ansible.cfg, "
                "or use_cli_login=true to use your `ss login` session."
            )

        results = []
        for term in terms:
            if self.get_option("render") or "%%" in term:
                if version_override is not None:
                    raise AnsibleError("Variable templates resolve current values; version is not supported")
                value = self._render(api_url, api_key, term, timeout)
            else:
                value = self._fetch_secret(api_url, api_key, term, version_override, timeout)
            results.append(value)

        return results

    def _render(self, api_url, api_key, template, timeout):
        payload = json.dumps({"template": template}).encode("utf-8")
        if len(payload) > 1024 * 1024:
            raise AnsibleError("SecretServer template exceeds size limit")
        req = Request(api_url + "/api/v1/variables/resolve", data=payload, headers={
            "Authorization": "Bearer " + api_key, "Content-Type": "application/json",
            "Accept": "application/json",
        }, method="POST")
        result = self._send(req, timeout, "SecretServer variable resolution failed")
        if not isinstance(result, dict) or not isinstance(result.get("rendered"), str):
            raise AnsibleError("SecretServer returned an invalid rendered response")
        return result["rendered"]

    def _send(self, req, timeout, failure):
        """Send a request without following redirects and return parsed JSON.

        Errors carry only the status code: never the key, URL or body.
        """
        try:
            opener = build_opener(ProxyHandler(getproxies_environment()), NoRedirect(), HTTPSHandler(context=self._ssl_context))
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            exc.close()
            raise AnsibleError("{} (HTTP {})".format(failure, exc.code)) from None
        except OSError:
            raise AnsibleError("SecretServer connection failed") from None
        if len(body) > MAX_RESPONSE_BYTES:
            raise AnsibleError("SecretServer response exceeds size limit")
        try:
            return json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise AnsibleError("SecretServer returned invalid JSON") from None

    def _fetch_secret(self, api_url, api_key, term, version_override, timeout):
        """Resolve the term to an API path and fetch the secret value."""

        parts = term.strip("/").split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise AnsibleError("Invalid SecretServer term: empty, '.' or '..' path segment")

        if len(parts) == 1:
            if version_override is not None and int(version_override) != 1:
                raise AnsibleError("Historical reads require container/name/version")
            # Bare name — direct name lookup
            path = "/api/v1/secrets/" + quote(parts[0], safe="")
            display.vvv("SecretServer: name lookup: {}".format(path))
        elif len(parts) == 2:
            # container/key
            container, key = parts
            version = version_override or 1
            if version == 1:
                path = "/api/v1/s/{}/{}".format(
                    quote(container, safe=""), quote(key, safe="")
                )
            else:
                path = "/api/v1/s/{}/{}/{}".format(
                    quote(container, safe=""), quote(key, safe=""), version
                )
            display.vvv("SecretServer: path lookup: {}".format(path))
        elif len(parts) == 3:
            # container/key/version
            container, key, ver_str = parts
            try:
                version = version_override or int(ver_str)
            except ValueError:
                raise AnsibleError("version must be an integer") from None
            if not 1 <= version <= 12:
                raise AnsibleError("version must be between 1 and 12")
            if version == 1:
                path = "/api/v1/s/{}/{}".format(
                    quote(container, safe=""), quote(key, safe="")
                )
            else:
                path = "/api/v1/s/{}/{}/{}".format(
                    quote(container, safe=""), quote(key, safe=""), version
                )
            display.vvv("SecretServer: versioned path lookup: {}".format(path))
        else:
            raise AnsibleError(
                "Invalid SecretServer term '{}'. "
                "Expected: 'key', 'container/key', or 'container/key/version'.".format(term)
            )

        url = api_url + path
        headers = {
            "Authorization": "Bearer " + api_key,
            "Accept": "application/json",
            "User-Agent": "ansible-lookup-secretserver/1.0",
        }

        req = Request(url, headers=headers)
        data = self._send(req, timeout, "SecretServer request failed")

        value = extract_value(data)

        display.vvv("SecretServer: fetched value for '{}'".format(term))
        return value


def cli_login_token():
    """Return (access token, API URL or None) from the `ss` CLI's SSO session.

    Uses the secretserver package's CLI provider (argv only, 30 s timeout,
    64 KiB cap). Its errors never contain the token.
    """
    try:
        from secretserver import SecretServerError, cli_credential_provider
    except ImportError:
        raise AnsibleError(
            "use_cli_login requires the secretserver Python package (1.4.0 or newer) on the controller"
        ) from None
    provider = cli_credential_provider()
    try:
        return provider(), provider.api_url()
    except SecretServerError as exc:
        raise AnsibleError("SecretServer CLI login failed: {}".format(exc)) from None


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_api_origin(raw):
    """Loose equality for the CLI-login/explicit-api_url mismatch check only:
    lowercases scheme and host, strips the scheme's default port (80 for
    http, 443 for https) and a trailing slash. Not a general URL comparison.
    """
    parts = urlsplit(raw)
    if not parts.scheme or not parts.hostname:
        return raw.lower().rstrip("/")
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None and ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        port = None
    netloc = host if port is None else "{}:{}".format(host, port)
    return "{}://{}{}".format(scheme, netloc, parts.path.rstrip("/"))


def same_api_origin(a, b):
    return normalize_api_origin(a) == normalize_api_origin(b)


def validate_api_url(api_url):
    """Return the normalized base URL, enforcing https except for loopback.

    Error messages never echo the URL because it may carry credentials.
    """
    url = api_url.strip().rstrip("/")
    if url.endswith("/api/v1"):
        url = url[:-7]
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 - raises ValueError on an invalid port
    except ValueError:
        raise AnsibleError("SecretServer api_url is not a valid URL") from None
    if "@" in parts.netloc:
        raise AnsibleError("SecretServer api_url must not contain credentials")
    if parts.query or parts.fragment or not host:
        raise AnsibleError("SecretServer api_url must be a plain https base URL")
    scheme = parts.scheme.lower()
    if scheme == "https" or (scheme == "http" and host in LOOPBACK_HOSTS):
        return url
    raise AnsibleError("SecretServer api_url must use https (plain http is allowed only for localhost)")


def make_ssl_context(ca_path=None):
    """Verifying TLS context; ca_path is added to the system trust store."""
    ctx = ssl.create_default_context()
    if ca_path:
        try:
            ctx.load_verify_locations(cafile=ca_path)
        except (OSError, ssl.SSLError):
            raise AnsibleError("SecretServer ca_path could not be loaded") from None
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def extract_value(response):
    if not isinstance(response, dict):
        raise AnsibleError("SecretServer returned an invalid secret envelope")
    sources = (response["data"],) if "data" in response else (response, response.get("meta"))
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in ("value", "password", "token", "key", "passphrase", "bind_password", "certificate"):
            if key in source and isinstance(source[key], str):
                return source[key]
    raise AnsibleError("SecretServer response contains no scalar secret; select a supported credential type")
