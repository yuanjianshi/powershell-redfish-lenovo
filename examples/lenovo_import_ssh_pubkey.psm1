﻿###
#
# Lenovo Redfish examples - import ssh pubkey
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


function lenovo_import_ssh_pubkey
{
    <#
   .Synopsis
    Cmdlet used to import ssh pubkey
   .DESCRIPTION
    Cmdlet used to import ssh pubkey from BMC using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - delusername: Pass in the account username you want to delete
    optional parameter:you can only use one option [sshpubkeyfile/sshpubkey] 
    - sshpubkeyfile:Pass in ssh pubkey you want to set
    - sshpubkey:Pass in file which contain ssh pubkey you want to set
   .EXAMPLE
    lenovo_import_ssh_pubkey -ip 10.10.10.10 -username USERID -password PASSW0RD -destusername NEWUSERNAME -sshpubkeyfile FILEPATH
   #>
   
    param
    (
        [Parameter(ParameterSetName='file',Mandatory=$True)]
        [string]$sshpubkeyfile,
        [Parameter(ParameterSetName='pubkey',Mandatory=$True)]
        [string]$sshpubkey,
        [Parameter(Mandatory=$True)]
        [string]$destusername,
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$False)]
        [string]$config_file="config.ini"
    )
        
    # Get configuration info from config file
    $ht_config_ini_info = read_config -config_file $config_file
    # If the parameter is not specified via command line, use the setting from configuration file
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
        $JsonHeader = @{ "X-Auth-Token" = $session_key}
      
        # Get the base url collection
        $manager_url_collection = @()
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object = $response.Content | ConvertFrom-Json

        #Get accountservice resource
        $url_account_service ="https://$ip" + $converted_object.AccountService."@odata.id"
        $response = Invoke-WebRequest -Uri $url_account_service -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object_account_service = $response.Content | ConvertFrom-Json

        #Get accounts resource
        $url_accounts = "https://$ip" + $converted_object_account_service.Accounts."@odata.id"
        $response = Invoke-WebRequest -Uri $url_accounts -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object = $response.Content | ConvertFrom-Json

        $list_url_account = @()
        foreach($url_account in $converted_object.Members)
        {
               $list_url_account += $url_account."@odata.id" 
        }

        #Get the dest url
        $url_dest = ""
        foreach($url_tmp_account in $list_url_account)
        {
            $url_account = "https://$ip" + $url_tmp_account
            $response = Invoke-WebRequest -Uri $url_account -Headers $JsonHeader -Method Get -UseBasicParsing 
            $converted_object = $response.Content | ConvertFrom-Json

            if($converted_object.UserName -eq $destusername)
            {
                $url_dest = $url_account
                break
            }
            else
            {
                continue
            }
        }
        if($url_dest -eq "")
        {
            Write-Host "accounts is not existed"
            return
        }

        $response = Invoke-WebRequest -Uri $url_dest -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object = $response.Content | ConvertFrom-Json

        $pubkey = ""
        if($sshpubkeyfile)
        {
            $pubkey = Get-Content -Path $sshpubkeyfile
        }

        if($sshpubkey)
        {
            $pubkey = $sshpubkey
        }

        if($converted_object.'@odata.etag' -ne $null)
        {
            $JsonHeader = @{ "If-Match" = $converted_object.'@odata.etag'
            "X-Auth-Token" = $session_key
            }
            $JsonBody = '{"Oem":{"Lenovo":{"SSHPublicKey":["'  +  $pubkey + '"]}}}'
        }
        else
        {
            $JsonHeader = @{ "If-Match" = ""
            "X-Auth-Token" = $session_key
                }

            $JsonBody = '{"Oem":{"Lenovo":{"SSHPublicKey":["'  +  $pubkey + '"]}}}'
        }

        $response = Invoke-WebRequest -Uri $url_dest -Method Patch -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
        Write-Host
                [String]::Format("- PASS, statuscode {0} returned successfully to import sshpukey",$response.StatusCode)
    }
    catch
    {
        # Handle http exception response
        if($_.Exception.Response)
        {
            Write-Host "Error occured, error code:" $_.Exception.Response.StatusCode.Value__
            if ($_.Exception.Response.StatusCode.Value__ -eq 401)
            {
                Write-Host "Error message: You are required to log on Web Server with valid credentials first."
            }
            elseif ($_.ErrorDetails.Message)
            {
                $response_j = $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand error
                $response_j = $response_j | Select-Object -Expand '@Message.ExtendedInfo'
                Write-Host "Error message:" $response_j.Resolution
            }
        } 
        # Handle system exception response
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