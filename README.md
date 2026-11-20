# constellation-identity

The identity service of the TechOrion Constellation platform. It is the source of truth for principals, roles, permissions, and tokens.

This version serves the OIDC discovery document and the JWKS. It manages ES256 signing keys with envelope encryption and rotation. It loads service clients and their public keys from a file. The token grants, the users, and the login come in later versions.

## Run

```sh
export IDENTITY_ISSUER=http://localhost:8080
export IDENTITY_DATABASE__URL=postgres://identity:<password>@localhost:5432/identity?sslmode=disable
export IDENTITY_DATABASE__NAME=identity
export IDENTITY_VALKEY__ADDRESS=localhost:6379
export IDENTITY_VALKEY__KEY_PREFIX=identity
export IDENTITY_SECRETS__MASTER_KEY="$(openssl rand -base64 32)"
export IDENTITY_SECRETS__MASTER_KEY_ID=k1
go run ./cmd/identity
```

Keep the master key. If it is lost, the signing keys are lost. See [docs/configuration.md](docs/configuration.md).

## Documentation

- [Configuration](docs/configuration.md)
- [Architecture](docs/architecture.md)
- [Development](docs/development.md)
