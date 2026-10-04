# Publishing the SecretServer clients

Nothing has been published yet. Until it is, every client installs straight
from git (see "Install from git" in [README.md](README.md)); this repository is
public, so that needs no GitHub access.

Package names are scoped to After Dark Systems because the bare name
`secretserver` is taken on PyPI by an unrelated project:

| Client | Registry | Name | Import name |
|---|---|---|---|
| Node.js | npm | `@afterdarksys/secretserver` | `@afterdarksys/secretserver` |
| Python | PyPI | `afterdarksys-secretserver` | `secretserver` |
| PHP | Packagist | `afterdarksys/secretserver` | `SecretServer\` (unchanged) |
| Go client | Go modules | `github.com/afterdarksys/secretserver-clients/go` | same |
| MCP server | Go modules | `github.com/afterdarksys/secretserver-clients/mcp` | binary |

Release from `main` only, after the branch is merged and every suite is green.
Version: `1.4.0`.

## 1. Check

```sh
(cd go && go vet ./... && go test -race ./...)
(cd go-gui && go vet ./... && go test -race ./...)
(cd mcp && go vet ./... && go test -race ./...)
(cd node && npm ci && npm test && npm pack --dry-run)
(cd php && composer validate --strict && composer test)
(cd python && rm -rf dist && uv build)
PYTHONPATH=python uv run --no-project --with pytest --with ansible-core python -m pytest -q python/tests ansible/tests
```

## 2. Tags (Go modules)

Go modules in subdirectories need path-prefixed tags:

```sh
git tag -a v1.4.0     -m "secretserver-clients 1.4.0"
git tag -a go/v1.4.0  -m "Go client 1.4.0"
git tag -a mcp/v1.4.0 -m "MCP server 1.4.0"
git push origin v1.4.0 go/v1.4.0 mcp/v1.4.0
```

Afterwards: `go get github.com/afterdarksys/secretserver-clients/go@v1.4.0`.
`go install …/mcp@v1.4.0` still fails because `mcp/go.mod` has a `replace
../go` directive; remove it (require `go v1.4.0` instead) in the next release
to make `go install` work.

## 3. npm

Needs an npm account that is a member of the `afterdarksys` org (create the org
on npmjs.com first if it does not exist).

```sh
cd node && npm ci && npm run build
npm publish --access public
```

## 4. PyPI

Needs a PyPI account and an API token scoped to the project (the first upload
creates `afterdarksys-secretserver`).

```sh
cd python && rm -rf dist && uv build
uvx twine check dist/*
uv publish            # prompts for the token, or UV_PUBLISH_TOKEN=...
```

## 5. Packagist

Packagist reads `composer.json` from the root of a git repository, so the PHP
client needs a split mirror repository. It does not exist yet:

```sh
gh repo create afterdarksys/secretserver-php --public \
  --description "PHP client for SecretServer.io (mirror of secretserver-clients/php)"
git subtree split -P php -b php-split
git push https://github.com/afterdarksys/secretserver-php.git php-split:main
git push https://github.com/afterdarksys/secretserver-php.git php-split:refs/tags/v1.4.0
```

Then submit `https://github.com/afterdarksys/secretserver-php` at
https://packagist.org/packages/submit (Packagist account needed) and enable the
GitHub hook so new tags publish automatically. Repeat the split + tag push for
every release.

## 6. Verify

```sh
npm view @afterdarksys/secretserver version
pip index versions afterdarksys-secretserver
composer show -a afterdarksys/secretserver
GOPROXY=proxy.golang.org go list -m github.com/afterdarksys/secretserver-clients/go@v1.4.0
```
