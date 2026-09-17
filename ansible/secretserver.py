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
        description: SecretServer API base URL.
        default: https://api.secretserver.io
        env:
          - name: SS_API_URL
        ini:
          - section: secretserver
            key: api_url
        type: str
      api_key:
        description: SecretServer API key.
        required: true
        env:
          - name: SS_API_KEY
        ini:
          - section: secretserver
            key: api_key
        type: str
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
      - Store the api_key in Ansible Vault, not in plaintext.
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

try:
    # Python 3
    from urllib.request import Request, urlopen, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler, getproxies_environment
    from urllib.error import HTTPError, URLError
    from urllib.parse import urljoin, quote
except ImportError:
    # Python 2 (legacy)
    from urllib2 import Request, urlopen, HTTPError, URLError
    from urlparse import urljoin
    from urllib import quote

display = Display()


class LookupModule(LookupBase):
    """SecretServer lookup plugin — retrieves secrets from SecretServer.io."""

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        api_url = self.get_option("api_url").rstrip("/")
        if api_url.endswith("/api/v1"):
            api_url = api_url[:-7]
        api_key = self.get_option("api_key")
        timeout = int(self.get_option("timeout"))
        version_override = self.get_option("version")
        if timeout <= 0:
            raise AnsibleError("timeout must be positive")
        if version_override is not None and not 1 <= int(version_override) <= 12:
            raise AnsibleError("version must be between 1 and 12")

        if not api_key:
            raise AnsibleError(
                "SecretServer API key is required. "
                "Set SS_API_KEY env var or secretserver.api_key in ansible.cfg."
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
        try:
            opener = build_opener(ProxyHandler(getproxies_environment()), NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise AnsibleError("SecretServer response exceeds size limit")
            result = json.loads(raw.decode("utf-8"))
            if not isinstance(result, dict) or not isinstance(result.get("rendered"), str):
                raise AnsibleError("SecretServer returned an invalid rendered response")
            return result["rendered"]
        except HTTPError as exc:
            exc.close()
            raise AnsibleError("SecretServer variable resolution failed (HTTP {})".format(exc.code)) from None
        except (URLError, ValueError, UnicodeError):
            raise AnsibleError("SecretServer variable resolution failed") from None

    def _fetch_secret(self, api_url, api_key, term, version_override, timeout):
        """Resolve the term to an API path and fetch the secret value."""

        parts = term.strip("/").split("/")

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
                raise AnsibleError("version must be an integer")
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

        # Allow self-signed certs in dev environments via SS_INSECURE=1
        import os
        ctx = None
        if os.environ.get("SS_INSECURE") == "1":
            msg = (
                "SecretServer lookup: TLS verification is DISABLED (SS_INSECURE=1). "
                "This must never be used in production."
            )
            try:
                self._display.warning(msg)
            except Exception:
                import sys
                print("WARNING: " + msg, file=sys.stderr)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            opener = build_opener(ProxyHandler(getproxies_environment()), NoRedirect(), HTTPSHandler(context=ctx or ssl.create_default_context()))
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                raise AnsibleError("SecretServer response exceeds size limit")
            data = json.loads(body.decode("utf-8"))
        except HTTPError as exc:
            raise AnsibleError("SecretServer API error {}".format(exc.code))
        except URLError as exc:
            raise AnsibleError(
                "SecretServer connection failed"
            )

        except (ValueError, UnicodeError):
            raise AnsibleError("SecretServer returned invalid JSON")

        value = extract_value(data)

        display.vvv("SecretServer: fetched value for '{}'".format(term))
        return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
