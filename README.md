# Local Hashicorp Vault

Very simple Docker Dompose setup to host a basic Hashicorp Vault.

## Install

```powershell
git clone https://github.com/flammalpha/local-hashicorp-vault-docker.git local-vault

cd local-vault

docker compose up -d

./configure-vault.ps1

./unseal-vault.ps1
```

## Features

- `vault-lib.psm1` contains many useful functions to communicate with basic and enterprise version of Hashicorp Vault

## Ressources

- <https://www.hashicorp.com/products/vault>
- <https://developer.hashicorp.com/vault/api-docs>
