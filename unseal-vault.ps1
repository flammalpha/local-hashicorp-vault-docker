Import-Module $PSScriptRoot/vault-lib.psm1 -Force

$InitResponse = Get-Content $PSScriptRoot/init_response.json | ConvertFrom-Json
$UnsealKey = $InitResponse.keys

Open-Vault -RootKey $UnsealKey

Write-Host "Vault Unsealed"