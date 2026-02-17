# -*- coding: utf-8 -*-
# (c) AfterDark Technologies
# GNU General Public License v3.0+

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
    name: secretserver
    author: AfterDark Technologies <support@secretserver.io>
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
      - Secret values are marked as no_log by Ansible automatically because
        this is a lookup plugin. Still avoid printing them in debug tasks.
      - Store the api_key in Ansible Vault, not in plaintext.
    seealso:
      - name: SecretServer API documentation
        link: https://secretserver.io/docs/api
    extends_documentation_fragment: []
"""

EXAMPLES = r"""
# Retrieve a secret by container/key path
- name: Set DB password from SecretServer
  ansible.builtin.set_fact:
    db_pass: "{{ lookup('secretserver', 'production/database-password') }}"

# Retrieve a historical version
- name: Get previous version of a cert
  ansible.builtin.set_fact:
    old_cert: "{{ lookup('secretserver', 'certs/wildcard-cert/2') }}"

# Use inline api_key (prefer Ansible Vault for this)
- name: Lookup with explicit key
  ansible.builtin.debug:
    msg: "{{ lookup('secretserver', 'prod/my-secret', api_key=vault_ss_key) }}"

# Multiple secrets in one lookup
- name: Gather multiple secrets
  ansible.builtin.set_fact:
    secrets: "{{ lookup('secretserver', 'prod/db-pass', 'prod/smtp-pass', wantlist=True) }}"

# Use in a template variable
- name: Configure nginx with secrets from SecretServer
  ansible.builtin.template:
    src: nginx.conf.j2
    dest: /etc/nginx/nginx.conf
  vars:
    tls_cert: "{{ lookup('secretserver', 'prod/nginx-tls-cert') }}"
    tls_key:  "{{ lookup('secretserver', 'prod/nginx-tls-key') }}"
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
    from urllib.request import Request, urlopen
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
        api_key = self.get_option("api_key")
        timeout = int(self.get_option("timeout"))
        version_override = self.get_option("version")

        if not api_key:
            raise AnsibleError(
                "SecretServer API key is required. "
                "Set SS_API_KEY env var or secretserver.api_key in ansible.cfg."
            )

        results = []
        for term in terms:
            value = self._fetch_secret(api_url, api_key, term, version_override, timeout)
            results.append(value)

        return results

    def _fetch_secret(self, api_url, api_key, term, version_override, timeout):
        """Resolve the term to an API path and fetch the secret value."""

        parts = term.strip("/").split("/")

        if len(parts) == 1:
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
            version = version_override or int(ver_str)
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
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            resp = urlopen(req, timeout=timeout, context=ctx) if ctx else urlopen(req, timeout=timeout)
            body = resp.read()
            data = json.loads(body.decode("utf-8"))
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise AnsibleError(
                "SecretServer API error {} for '{}': {}".format(exc.code, term, body)
            )
        except URLError as exc:
            raise AnsibleError(
                "SecretServer connection error for '{}': {}".format(term, str(exc))
            )

        # The API returns {"value": "..."} for secret lookups
        if "value" not in data:
            raise AnsibleError(
                "SecretServer: unexpected response format for '{}': {}".format(
                    term, json.dumps(data)[:200]
                )
            )

        display.vvv("SecretServer: fetched value for '{}'".format(term))
        return data["value"]
