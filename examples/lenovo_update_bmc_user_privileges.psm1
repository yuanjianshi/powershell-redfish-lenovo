###
#
# Lenovo Redfish examples - Update BMC User Privileges
#
# Copyright Notice:
#
# Copyright 2018 Lenovo Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
###


###
#  Import utility libraries
###
Import-module $PSScriptRoot\lenovo_utils.psm1


function lenovo_update_bmc_user_privileges
{
   <#
   .Synopsis
    Cmdlet used to update BMC user privileges
   .DESCRIPTION
    Cmdlet used to update BMC user privileges using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - bmcuser: UserID to be modified by the user
    - authority: New privileges to be modified by the user.The value of this parameter shall be the privileges that this user includes. For super user, this property shall be Supervisor. default is super user. For pre-defined user, this property shall be ReadOnly. For custom user some implementations may not allow writing this property. You can only choose one or more values in the list:[UserAccountManagement,RemoteConsoleAccess,RemoteConsoleAndVirtualMediaAcccess,RemoteServerPowerRestartAccess,AbilityClearEventLogs,AdapterConfiguration_Basic,AdapterConfiguration_NetworkingAndSecurity,AdapterConfiguration_Advanced]
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_update_bmc_user_privileges -ip 10.10.10.10 -username USERID -password PASSW0RD -bmcuser BMCUSER -anthority @("AUTHORITY", "AUTHORITY")
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$True)]
        [string]$bmcuser="",
        [Parameter(Mandatory=$True)]
        [array]$authority="",
        [Parameter(Mandatory=$False)]
        [string]$config_file="config.ini"
        )
        
    # get configuration info from config file
    $ht_config_ini_info = read_config -config_file $config_file

    # if the parameter is not specified via command line, use the setting from configuration file
    if ($ip -eq "")
    {
        $ip = [string]($ht_config_ini_info['BmcIp'])
    }
    if ($username -eq "")
    {
        $username = [string]($ht_config_ini_info['BmcUsername'])
    }
    if ($password -eq "")
    {
        $password = [string]($ht_config_ini_info['BmcUserpassword'])
    }

    try
    {
        $session_key = ""
        $session_location = ""

        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        # Build headers with session key for authentication
        $JsonHeader = @{ "X-Auth-Token" = $session_key
        }

        # check connection
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        
        # convert response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        $account_server_url_string = "https://$ip"+$hash_table.AccountService.'@odata.id'

        # get the accounts url via Invoke-WebRequest
        $response_account_server = Invoke-WebRequest -Uri $account_server_url_string -Headers $JsonHeader -Method Get -UseBasicParsing

        # convert response_account_server content to hash table
        $converted_object = $response_account_server.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        $accounts_url_string = "https://$ip"+$hash_table.Accounts.'@odata.id'

        # get the account url via Invoke-WebRequest
        $response_accounts_url = Invoke-WebRequest -Uri $accounts_url_string -Headers $JsonHeader -Method Get -UseBasicParsing

        # convert response_accounts_url content to hash table
        $converted_object = $response_accounts_url.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        foreach ($i in $hash_table.Members)
        {
            $account_url = "https://$ip" + $i.'@odata.id'
            # Get account information if account is valid (UserName not blank)
            $response_account_x_url = Invoke-WebRequest -Uri $account_url -Headers $JsonHeader -Method Get -UseBasicParsing

            # convert response_account_x_url content to hash table
            $converted_object = $response_account_x_url.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

            if($hash_table.UserName -eq $bmcuser)
            {
                if($hash_table.'@odata.etag' -ne $null)
                {
                    $Json_Header = @{ "If-Match" = $hash_table.'@odata.etag'
                    "X-Auth-Token" = $session_key
                    } 
                }
                else
                {
                    $Json_Header = @{ "If-Match" = ""
                    "X-Auth-Token" = $session_key
                        }
                }
                # Check BMC user privileges
                $custom_privileges_list = @("Supervisor","ReadOnly","UserAccountManagement","RemoteConsoleAccess","RemoteConsoleAndVirtualMediaAcccess","RemoteServerPowerRestartAccess","AbilityClearEventLogs","AdapterConfiguration_Basic"
,"AdapterConfiguration_NetworkingAndSecurity","AdapterConfiguration_Advanced")
                foreach($custom_privileges in $authority)
                {
                    if($custom_privileges_list -notcontains $custom_privileges)
                    {
                        write-Host 'You can specify ReadOnly or Supervisor, or choose one or more custom privileges from list: ["UserAccountManagement","RemoteConsoleAccess","RemoteConsoleAndVirtualMediaAcccess","RemoteServerPowerRestartAccess","AbilityClearEventLogs","AdapterConfiguration_Basic"
,"AdapterConfiguration_NetworkingAndSecurity","AdapterConfiguration_Advanced"]'
                        return $False
                    }
                }

                # Get the current BMC user role id
                $role_uri = "https://$ip" + $hash_table.Links.Role.'@odata.id'
                $custom_body = @{"OemPrivileges" = $authority}
                $CustomJsonBody = $custom_body | ConvertTo-Json
                 
                # Update custom Oem privileges
                $response = Invoke-WebRequest -Uri $role_uri -Method Patch -Headers $JsonHeader -Body $CustomJsonBody -ContentType 'application/json' -UseBasicParsing
                Write-Host
                [String]::Format("- PASS, statuscode {0} returned. The BMC user {1} privileges is successfully updated.",$response.StatusCode, $bmcuser)
                return $True
            }
        }
        write-Host "Specified BMC username doesn't exist. Please check whether the BMC username is correct."
        return $False
    }
    catch
    {
        if($_.Exception.Response)
        {
            Write-Host "Error occured, error code:" $_.Exception.Response.StatusCode.Value__
            $info=$_.InvocationInfo
            [String]::Format("`n-Error occured!file:{0} line:{1},col:{2},msg:{3},fullname:{4}`n" ,$info.ScriptName,$info.ScriptLineNumber,$info.OffsetInLine ,$_.Exception.Message,$_.Exception.GetType().FullName)
            if ($_.Exception.Response.StatusCode.Value__ -eq 401)
            {
                Write-Host "Error message: You are required to log on Web Server with valid credentials first."
            }
            if ($_.ErrorDetails.Message)
            {
                $response_j = $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand error
                $response_j = $response_j | Select-Object -Expand '@Message.ExtendedInfo'
                Write-Host "Error message:" $response_j.Resolution
                $info=$_.InvocationInfo
                [String]::Format("`n-Error occured!file:{0} line:{1},col:{2},msg:{3},fullname:{4}`n" ,$info.ScriptName,$info.ScriptLineNumber,$info.OffsetInLine ,$_.Exception.Message,$_.Exception.GetType().FullName)
            }
        } 
        elseif($_.Exception)
        {
            Write-Host "Error message:" $_.Exception.Message
            Write-Host "Please check arguments or server status."
        }
        return $False
    }
    # Delete existing session whether script exit successfully or not
    finally
    {
        if ($session_key -ne "")
        {
            delete_session -ip $ip -session $session
        }
    }
}