function Initialize-Vault {
    #Output?
    [OutputType([hashtable], ParameterSetName = ("Default"))]
    Param(
        #Input?
        [Parameter(Mandatory = $false, HelpMessage = "API URL (FQDN of Host)", ParameterSetName = 'Default')]
        [String]
        $ApiUri = "http://localhost:8200/",
        [Parameter(Mandatory = $false, HelpMessage = "Secret Shares (Default 1)", ParameterSetName = 'Default')]
        [int]
        $SecretShares = 1,
        [Parameter(Mandatory = $false, HelpMessage = "Secret Threshold (Default 1)", ParameterSetName = 'Default')]
        [int]
        $SecretThreshold = 1
    )
    ############################################################################################################################################
    Write-Debug "Start-Function: '$($MyInvocation.MyCommand)'"
    $PSBoundParameters.GetEnumerator() | ForEach-Object -Begin { Write-Debug "######### Passed Parameter #########" } -Process { Write-Debug (" - " + $_.key + ": " + $_.value) } -End { Write-Debug "####################################" }
    ############################################################################################################################################
    #Implementation
    $InitPayload = @{
        "secret_shares"    = $SecretShares
        "secret_threshold" = $SecretThreshold
    } | ConvertTo-Json
    $InitUri = $ApiUri.TrimEnd("/") + "/v1/sys/init"

    Write-Debug "Initializing Vault"
    $InitResponse = Invoke-WebRequest -Method Post -Uri $InitUri -Body $InitPayload -SkipCertificateCheck

    Set-Content ./init_response.json -Value $InitResponse
    ############################################################################################################################################
    Write-Debug "End-Function '$($MyInvocation.MyCommand)'"
    ############################################################################################################################################
    return $InitResponse | ConvertFrom-Json
}

function Enable-UserAuth {
    #Output?
    Param(
        [Parameter(Mandatory = $false, HelpMessage = "API URL (FQDN of Host)", ParameterSetName = 'Default')]
        [String]
        $ApiUri = "http://localhost:8200/",
        # Keytoken
        [Parameter(Mandatory = $true, HelpMessage = "Vault Token", ParameterSetName = "Default")]
        [string]
        $Token
    )
    ############################################################################################################################################
    Write-Debug "Start-Function: '$($MyInvocation.MyCommand)'"
    $PSBoundParameters.GetEnumerator() | ForEach-Object -Begin { Write-Debug "######### Passed Parameter #########" } -Process { Write-Debug (" - " + $_.key + ": " + $_.value) } -End { Write-Debug "####################################" }
    ############################################################################################################################################
    #Implementation
    $RootHeader = @{
        "X-Vault-Token" = "$Token"
    }
    $AuthPayload = @{
        "type" = "userpass"
    } | ConvertTo-Json
    $AuthUri = $ApiUri.TrimEnd("/") + "/v1/sys/auth/userpass"

    Write-Debug "Enabling Userpass Auth"
    $AuthResponse = Invoke-WebRequest -Method Post -Uri $AuthUri -Headers $RootHeader -Body $AuthPayload -SkipCertificateCheck
    ############################################################################################################################################
    Write-Debug "End-Function '$($MyInvocation.MyCommand)'"
    ############################################################################################################################################
    return $AuthResponse | ConvertFrom-Json
}

function Add-User {
    #Output?
    Param(
        [Parameter(Mandatory = $false, HelpMessage = "API URL (FQDN of Host)", ParameterSetName = 'Default')]
        [String]
        $ApiUri = "http://localhost:8200/",
        # Keytoken
        [Parameter(Mandatory = $true, HelpMessage = "Vault Token", ParameterSetName = "Default")]
        [string]
        $Token,
        [Parameter(Mandatory = $true, HelpMessage = "Name of the user", ParameterSetName = 'Default')]
        [string]
        $Name,
        [Parameter(Mandatory = $false, HelpMessage = "Password of the user", ParameterSetName = 'Default')]
        [pscredential]
        $Password,
        [Parameter(Mandatory = $false, HelpMessage = "Additional Policies", ParameterSetName = 'Default')]
        [string[]]
        $AdditionalPolicies
    )
    ############################################################################################################################################
    Write-Debug "Start-Function: '$($MyInvocation.MyCommand)'"
    $PSBoundParameters.GetEnumerator() | ForEach-Object -Begin { Write-Debug "######### Passed Parameter #########" } -Process { Write-Debug (" - " + $_.key + ": " + $_.value) } -End { Write-Debug "####################################" }
    ############################################################################################################################################
    #Implementation
    $RootHeader = @{
        "X-Vault-Token" = "$Token"
    }
    $Policies = New-Object System.Collections.ArrayList
    $Policies.Add("Default")
    if ($null -ne $AdditionalPolicies) {

        $Policies.AddRange($AdditionalPolicies)
    }
    $UserPayload = @{
        "password"       = $Password.GetNetworkCredential().Password
        "token_policies" = $Policies
    } | ConvertTo-Json
    $UserUri = $ApiUri.TrimEnd("/") + "/v1/auth/userpass/users/admin"
    
    Write-Debug "Create User"
    $UserResponse = Invoke-WebRequest -Method Post -Uri $UserUri -Headers $RootHeader -Body $UserPayload -SkipCertificateCheck
    ############################################################################################################################################
    Write-Debug "End-Function '$($MyInvocation.MyCommand)'"
    ############################################################################################################################################
    return $UserResponse | ConvertFrom-Json
}

function Open-Vault {
    #Output?
    Param(
        [Parameter(Mandatory = $false, HelpMessage = "API URL (FQDN of Host)", ParameterSetName = 'Default')]
        [String]
        $ApiUri = "http://localhost:8200/",
        [Parameter(Mandatory = $true, HelpMessage = "Vault Key", ParameterSetName = 'Default')]
        [String]
        $RootKey
    )
    ############################################################################################################################################
    Write-Debug "Start-Function: '$($MyInvocation.MyCommand)'"
    $PSBoundParameters.GetEnumerator() | ForEach-Object -Begin { Write-Debug "######### Passed Parameter #########" } -Process { Write-Debug (" - " + $_.key + ": " + $_.value) } -End { Write-Debug "####################################" }
    ############################################################################################################################################
    #Implementation
    $UnsealPayload = @{
        "key" = "$RootKey"
    } | ConvertTo-Json
    $UnsealUri = $ApiUri.TrimEnd("/") + "/v1/sys/unseal"

    Write-Debug "Unsealing Vault"
    $UnsealResponse = Invoke-WebRequest -Method Post -Uri $UnsealUri -Body $UnsealPayload -SkipCertificateCheck
    ############################################################################################################################################
    Write-Debug "End-Function '$($MyInvocation.MyCommand)'"
    ############################################################################################################################################
    return $UnsealResponse | ConvertFrom-Json
}

function Close-Vault {
    #Output?
    Param(
        [Parameter(Mandatory = $false, HelpMessage = "API URL (FQDN of Host)", ParameterSetName = 'Default')]
        [String]
        $ApiUri = "http://localhost:8200/",
        # Keytoken
        [Parameter(Mandatory = $true, HelpMessage = "Token with Admin rights", ParameterSetName = "Default")]
        [string]
        $Token
    )
    ############################################################################################################################################
    Write-Debug "Start-Function: '$($MyInvocation.MyCommand)'"
    $PSBoundParameters.GetEnumerator() | ForEach-Object -Begin { Write-Debug "######### Passed Parameter #########" } -Process { Write-Debug (" - " + $_.key + ": " + $_.value) } -End { Write-Debug "####################################" }
    ############################################################################################################################################
    #Implementation
    ############################################################################################################################################
    Write-Debug "End-Function '$($MyInvocation.MyCommand)'"
    ############################################################################################################################################
}

function Add-VaultEngine {
    #Output?
    Param(
        [Parameter(Mandatory = $false, HelpMessage = "API URL (FQDN of Host)", ParameterSetName = 'Default')]
        [String]
        $ApiUri = "http://localhost:8200/",
        # Keytoken
        [Parameter(Mandatory = $true, HelpMessage = "Token with Admin rights", ParameterSetName = "Default")]
        [string]
        $Token,
        [Parameter(Mandatory = $false, HelpMessage = "Name of the Secrets Engine", ParameterSetName = 'Default')]
        [String]
        $Name = "kv"
    )
    ############################################################################################################################################
    Write-Debug "Start-Function: '$($MyInvocation.MyCommand)'"
    $PSBoundParameters.GetEnumerator() | ForEach-Object -Begin { Write-Debug "######### Passed Parameter #########" } -Process { Write-Debug (" - " + $_.key + ": " + $_.value) } -End { Write-Debug "####################################" }
    ############################################################################################################################################
    #Implementation
    $RootHeader = @{
        "X-Vault-Token" = "$Token"
    }
    $KVPayload = @{
        "type"    = "kv"
        "config"  = @{
            "Default_lease_ttl" = 0
            "force_no_cache"    = $false
            "max_lease_ttl"     = 0
        }
        "options" = @{
            "version" = "2"
        }
    } | ConvertTo-Json
    $KVUri = $ApiUri.TrimEnd("/") + "/v1/sys/mounts/$Name"
    
    Write-Debug "Creating/Mounting KV Engine"
    $KVResponse = Invoke-WebRequest -Method Post -Uri $KVUri -Headers $RootHeader -Body $KVPayload -SkipCertificateCheck
    ############################################################################################################################################
    Write-Debug "End-Function '$($MyInvocation.MyCommand)'"
    ############################################################################################################################################
    return $KVResponse | ConvertFrom-Json
}

function Add-ACLPolicy {
    #Output?
    Param(
        [Parameter(Mandatory = $false, HelpMessage = "API URL (FQDN of Host)", ParameterSetName = 'Default')]
        [String]
        $ApiUri = "http://localhost:8200/",
        # Keytoken
        [Parameter(Mandatory = $true, HelpMessage = "Token with Admin rights", ParameterSetName = "Default")]
        [String]
        $Token,
        [Parameter(Mandatory = $true, HelpMessage = "Name of Policy", ParameterSetName = 'Default')]
        [String]
        $PolicyName,
        [Parameter(Mandatory = $true, HelpMessage = "Policy Content", ParameterSetName = 'Default')]
        [String]
        $PolicyContent
    )
    ############################################################################################################################################
    Write-Debug "Start-Function: '$($MyInvocation.MyCommand)'"
    $PSBoundParameters.GetEnumerator() | ForEach-Object -Begin { Write-Debug "######### Passed Parameter #########" } -Process { Write-Debug (" - " + $_.key + ": " + $_.value) } -End { Write-Debug "####################################" }
    ############################################################################################################################################
    #Implementation
    $RootHeader = @{
        "X-Vault-Token" = "$Token"
    }
    $ACLPayload = @{
        "policy" = "$PolicyContent"
    } | ConvertTo-Json
    $ACLUri = $ApiUri.TrimEnd("/") + "/v1/sys/policies/acl/$PolicyName"
    
    Write-Debug "Creating ACL Policy"
    $ACLResponse = Invoke-WebRequest -Method Post -Uri $ACLUri -Headers $RootHeader -Body $ACLPayload -SkipCertificateCheck
    ############################################################################################################################################
    Write-Debug "End-Function '$($MyInvocation.MyCommand)'"
    ############################################################################################################################################
    return $ACLResponse | ConvertFrom-Json
} 

function Get-UserToken {
    #Output?
    [OutputType([string], ParameterSetName = ("Default"))]
    Param(
        [Parameter(Mandatory = $false, HelpMessage = "API URL (FQDN of Host)", ParameterSetName = 'Default')]
        [String]
        $ApiUri = "http://localhost:8200/",
        # User to log into vault
        [Parameter(Mandatory = $false, HelpMessage = "Login type ('ldap')", ParameterSetName = "Default")]
        [ValidateSet("ldap", "userpass")]
        [String]
        $AuthMethod = "userpass",
        [Parameter(Mandatory = $false, HelpMessage = "Username", ParameterSetName = "Default")]
        [String]
        $UserName = "admin",
        # Password for user
        [Parameter(Mandatory = $false, HelpMessage = "PSCredentials for password", ParameterSetName = "Default")]
        [pscredential]
        $Password = $null,
        # Vault namespace
        [Parameter(Mandatory = $false, HelpMessage = "Namespace for Enterprise Vault", ParameterSetName = "Default")]
        [string]
        $NameSpace = $null
    )
    ############################################################################################################################################
    Write-Debug "Start-Function: '$($MyInvocation.MyCommand)'"
    $PSBoundParameters.GetEnumerator() | ForEach-Object -Begin { Write-Debug "######### Passed Parameter #########" } -Process { Write-Debug (" - " + $_.key + ": " + $_.value) } -End { Write-Debug "####################################" }
    ############################################################################################################################################
    #Implementation
    $LoginUri = $ApiUri.TrimEnd("/") + "/v1/auth/$AuthMethod/login/$UserName"
    $LoginPayload = @{}
    if ($null -ne $Password) {
        $LoginPayload.Add("password", $Password.GetNetworkCredential().Password)
    }
    else {
        $VaultCredentials = Get-Credential -UserName $UserName -Message "Vault: $ApiUri $NameSpace"
        $LoginPayload.Add("password", $VaultCredentials.GetNetworkCredential().Password)
    }
    $LoginHeader = @{}
    if ($null -ne $NameSpace) {
        $LoginHeader.Add("X-Vault-Namespace", $NameSpace)
    }

    Write-Debug "Login into vault"
    $LoginResponse = Invoke-WebRequest -Method Post -Uri $LoginUri -Headers $LoginHeader -Body $LoginPayload -SkipCertificateCheck | ConvertFrom-Json 
    ############################################################################################################################################
    Write-Debug "End-Function '$($MyInvocation.MyCommand)'"
    ############################################################################################################################################
    return $LoginResponse.auth.client_token
}

function Get-Secret {
    #Output?
    Param(
        [Parameter(Mandatory = $false, HelpMessage = "API URL (FQDN of Host)", ParameterSetName = 'Default')]
        [String]
        $ApiUri = "http://localhost:8200/",
        # Vault access token
        [Parameter(Mandatory = $true, HelpMessage = "Token with Access rights", ParameterSetName = "Default")]
        [string]
        $Token,
        # Vault secret engine
        [Parameter(Mandatory = $false, HelpMessage = "Name of the secret engine", ParameterSetName = "Default")]
        [string]
        $SecretEngine = "kv",
        # Vault secret path
        [Parameter(Mandatory = $true, HelpMessage = "Path to the secret", ParameterSetName = "Default")]
        [string]
        $SecretPath,
        # Vault namespace
        [Parameter(Mandatory = $false, HelpMessage = "Namespace for Enterprise Vault", ParameterSetName = "Default")]
        [string]
        $NameSpace = $null
    )
    ############################################################################################################################################
    Write-Debug "Start-Function: '$($MyInvocation.MyCommand)'"
    $PSBoundParameters.GetEnumerator() | ForEach-Object -Begin { Write-Debug "######### Passed Parameter #########" } -Process { Write-Debug (" - " + $_.key + ": " + $_.value) } -End { Write-Debug "####################################" }
    ############################################################################################################################################
    #Implementation
    $VaultUri = $ApiUri.TrimEnd("/") + "/v1/$SecretEngine/data/$($SecretPath.TrimStart("/"))"

    $AuthHeader = @{ "X-Vault-Token" = "$Token" }
    if ($null -ne $NameSpace) {
        $AuthHeader.Add("X-Vault-Namespace", "$NameSpace")
    }

    Write-Debug "Fetching Secret"
    $VaultResponse = Invoke-WebRequest -Method Get -Uri $VaultUri -Headers $AuthHeader -SkipCertificateCheck | ConvertFrom-Json

    $ConvertedContent = @{}

    foreach ($Entry in $VaultResponse.data.data.psobject.Properties) {
        $ConvertedContent.Add($Entry.Name, $Entry.Value)
    }
    ############################################################################################################################################
    Write-Debug "End-Function '$($MyInvocation.MyCommand)'"
    ############################################################################################################################################
    return $ConvertedContent
}

function Set-Secret {
    #Output?
    Param(
        [Parameter(Mandatory = $false, HelpMessage = "API URL (FQDN of Host)", ParameterSetName = 'Default')]
        [String]
        $ApiUri = "http://localhost:8200/",
        # Vault access token
        [Parameter(Mandatory = $true, HelpMessage = "Token with Access rights", ParameterSetName = "Default")]
        [string]
        $Token,
        # Vault secret engine
        [Parameter(Mandatory = $false, HelpMessage = "Name of the secret engine", ParameterSetName = "Default")]
        [string]
        $SecretEngine = "kv",
        # Vault secret path
        [Parameter(Mandatory = $true, HelpMessage = "Path to the secret", ParameterSetName = "Default")]
        [string]
        $SecretPath,
        # Vault namespace
        [Parameter(Mandatory = $false, HelpMessage = "Namespace for Enterprise Vault", ParameterSetName = "Default")]
        [string]
        $NameSpace = $null,
        # Secret Data
        [Parameter(Mandatory = $true, HelpMessage = "Secret Data Hashmap", ParameterSetName = "Default")]
        [hashtable]
        $SecretData
    )
    ############################################################################################################################################
    Write-Debug "Start-Function: '$($MyInvocation.MyCommand)'"
    $PSBoundParameters.GetEnumerator() | ForEach-Object -Begin { Write-Debug "######### Passed Parameter #########" } -Process { Write-Debug (" - " + $_.key + ": " + $_.value) } -End { Write-Debug "####################################" }
    ############################################################################################################################################
    #Implementation
    $VaultUri = $ApiUri.TrimEnd("/") + "/v1/$SecretEngine/data/$($SecretPath.TrimStart("/"))"

    $AuthHeader = @{ "X-Vault-Token" = "$Token" }
    if ($null -ne $NameSpace) {
        $AuthHeader.Add("X-Vault-Namespace", "$NameSpace")
    }

    $SecretBody = @{}

    if ($SecretData.ContainsKey("data") -and $SecretData.data.GetType().name -eq "Hashtable") {
        $SecretBody = $SecretData | ConvertTo-Json
    }
    else {
        $SecretBody = @{"data" = $SecretData } | ConvertTo-Json
    }

    Write-Debug "Creating/Updating Secret"
    $VaultResponse = Invoke-WebRequest -Method Post -Uri $VaultUri -Headers $AuthHeader -Body $SecretBody -SkipCertificateCheck
    ############################################################################################################################################
    Write-Debug "End-Function '$($MyInvocation.MyCommand)'"
    ############################################################################################################################################
    return $VaultResponse | ConvertFrom-Json
}

function Update-Secret {
    #Output?
    Param(
        [Parameter(Mandatory = $false, HelpMessage = "API URL (FQDN of Host)", ParameterSetName = 'Default')]
        [String]
        $ApiUri = "http://localhost:8200/",
        # Vault access token
        [Parameter(Mandatory = $true, HelpMessage = "Token with Access rights", ParameterSetName = "Default")]
        [string]
        $Token,
        # Vault secret engine
        [Parameter(Mandatory = $false, HelpMessage = "Name of the secret engine", ParameterSetName = "Default")]
        [string]
        $SecretEngine = "kv",
        # Vault secret path
        [Parameter(Mandatory = $false, HelpMessage = "Path to the secret", ParameterSetName = "Default")]
        [string]
        $SecretPath,
        # Vault namespace
        [Parameter(Mandatory = $false, HelpMessage = "Namespace for Enterprise Vault", ParameterSetName = "Default")]
        [string]
        $NameSpace = $null
    )
    ############################################################################################################################################
    Write-Debug "Start-Function: '$($MyInvocation.MyCommand)'"
    $PSBoundParameters.GetEnumerator() | ForEach-Object -Begin { Write-Debug "######### Passed Parameter #########" } -Process { Write-Debug (" - " + $_.key + ": " + $_.value) } -End { Write-Debug "####################################" }
    ############################################################################################################################################
    #Implementation
    return "Not yet implemented"

    $VaultUri = $ApiUri.TrimEnd("/") + "/v1/$SecretEngine/data/$($SecretPath.TrimStart("/"))"

    $AuthHeader = @{ "X-Vault-Token" = "$Token" }
    if ($null -ne $NameSpace) {
        $AuthHeader.Add("X-Vault-Namespace", "$NameSpace")
    }

    Write-Debug "Updating Secret"
    $VaultResponse = Invoke-WebRequest -Method Patch -Uri $VaultUri -Headers $AuthHeader -Body $SecretData -SkipCertificateCheck
    ############################################################################################################################################
    Write-Debug "End-Function '$($MyInvocation.MyCommand)'"
    ############################################################################################################################################
    return $VaultResponse | ConvertFrom-Json
}

function Remove-Secret {
    #Output?
    Param(
        [Parameter(Mandatory = $false, HelpMessage = "API URL (FQDN of Host)", ParameterSetName = 'Default')]
        [String]
        $ApiUri = "http://localhost:8200/",
        # Vault access token
        [Parameter(Mandatory = $true, HelpMessage = "Token with Access rights", ParameterSetName = "Default")]
        [string]
        $Token,
        # Vault secret path
        [Parameter(Mandatory = $false, HelpMessage = "Path to the secret", ParameterSetName = "Default")]
        [string]
        $SecretPath,
        # Vault namespace
        [Parameter(Mandatory = $false, HelpMessage = "Namespace for Enterprise Vault", ParameterSetName = "Default")]
        [string]
        $NameSpace = $null
    )
    ############################################################################################################################################
    Write-Debug "Start-Function: '$($MyInvocation.MyCommand)'"
    $PSBoundParameters.GetEnumerator() | ForEach-Object -Begin { Write-Debug "######### Passed Parameter #########" } -Process { Write-Debug (" - " + $_.key + ": " + $_.value) } -End { Write-Debug "####################################" }
    ############################################################################################################################################
    #Implementation
    $VaultUri = $ApiUri.TrimEnd("/") + "/v1/$SecretEngine/data/$($SecretPath.TrimStart("/"))"

    $AuthHeader = @{ "X-Vault-Token" = "$Token" }
    if ($null -ne $NameSpace) {
        $AuthHeader.Add("X-Vault-Namespace", "$NameSpace")
    }

    Write-Debug "Delete Secret"
    $VaultResponse = Invoke-WebRequest -Method Delete -Uri $VaultUri -Headers $AuthHeader -SkipCertificateCheck
    ############################################################################################################################################
    Write-Debug "End-Function '$($MyInvocation.MyCommand)'"
    ############################################################################################################################################
    return $VaultResponse | ConvertFrom-Json
}