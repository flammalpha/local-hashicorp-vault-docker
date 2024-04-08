Import-Module $PSScriptRoot/vault-lib.psm1 -Force

############ Init
$InitJSON = Initialize-Vault
$RootToken = $InitJSON.root_token
$RootKey = $InitJSON.keys[0]

############ Unseal
Open-Vault -RootKey $RootKey

############ KV Engine
Add-VaultEngine -Token $RootToken

############ ACL
$AdminPolicyName = "admin"
$AdminPolicy = Get-Content $PSScriptRoot/admin_policy.hcl -Raw
Add-ACLPolicy -Token $RootToken -PolicyName $AdminPolicyName -PolicyContent $AdminPolicy

############ UserAuth
Enable-UserAuth -Token $RootToken

############ User
$AdminName = "admin"
$AdminPW = ConvertTo-SecureString $AdminName -AsPlainText -Force
$AdminCred = New-Object pscredential ($AdminName, $AdminPW)
Add-User -Token $RootToken -Name $AdminName -Password $AdminCred -AdditionalPolicies @($AdminPolicyName)

############
Write-Host "Vault Initialized!"
Write-Host "Access with admin/admin on http://localhost:8200/ui"
Write-Host 'Root token in "init_response.json"'