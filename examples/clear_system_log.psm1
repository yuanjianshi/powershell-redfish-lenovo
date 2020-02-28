###
#
# Lenovo Redfish examples - Clear system log
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


function clear_system_log
{
   <#
   .Synopsis
    Cmdlet used to clear system log
   .DESCRIPTION
    Cmdlet used to clear system log from BMC using Redfish API. Clear result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - type : Pass in System log type
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    clear_system_log -ip 10.10.10.10 -username USERID -password PASSW0RD -type Chassis -config_file config.ini
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string] $ip = '',
        [Parameter(Mandatory=$False)]
        [string] $username = '',
        [Parameter(Mandatory=$False)]
        [string] $password = '',
        [Parameter(Mandatory=$True)]
        [string] $type = '',
        [Parameter(Mandatory=$False)]
        [string] $config_file = 'config.ini'
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
        $session_key = $session_location = ''
        
        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        # Build headers with sesison key for authentication
        $JsonHeader = @{ 'X-Auth-Token' = $session_key}

        $url_collection = @()
        $resource_rul_collection = @()
        $checked_logservice_collection = @()

        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json

        $chassis_url = $converted_object.Chassis."@odata.id"
        $managers_url = $converted_object.Managers."@odata.id"
        $systems_url = $converted_object.Systems."@odata.id"
        
        if($type -eq "Chassis")
        {
            $resource_rul_collection += $chassis_url
        }
        elseif($type -eq "Managers")
        {
            $resource_rul_collection += $managers_url
        }
        elseif($type -eq "Systems")
        {
            $resource_rul_collection += $systems_url
        }
        else 
        {
            Write-Host "Please check log type. choice:'Chassis', 'Managers', 'Systems'"
            return $False
        }

        foreach ($resource_url in $resource_rul_collection)
        {

            $resource_url_string = "https://$ip" + $resource_url
            $response = Invoke-WebRequest -Uri $resource_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
    
            # Convert response content to hash table
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | ForEach-Object { $hash_table[$_.Name] = $_.Value }
    
            foreach ($i in $hash_table.Members)
            {
                $i = [string]$i
                $resource_url_string = ($i.Split("=")[1].Replace("}",""))
                $url_collection += $resource_url_string
            }
        }

        # Loop all resource instance in $url_collection
        foreach ($url_collection_string in $url_collection)
        {
            $uri_address = "https://$ip"+$url_collection_string
            # Get the response manager resource
            $response_uri_address = Invoke-WebRequest -Uri $uri_address -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response_uri_address.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | ForEach-Object { $hash_table[$_.Name] = $_.Value }
            $log_services_url_string = "https://$ip" + $hash_table.LogServices.'@odata.id'

            if ($checked_logservice_collection -notcontains $log_services_url_string)
            {
                perform_log_clear -log_services_url_string $log_services_url_string -JsonHeader $JsonHeader
                $checked_logservice_collection += $log_services_url_string
            }
        }
        
        Write-Host
        [String]::Format("Successfully to clear all system log")
        return $True 

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
        if (-not [string]::IsNullOrWhiteSpace($session_key))
        {
            delete_session -ip $ip -session $session
        }
    }
}

function perform_log_clear() 
{

    param (
        [Parameter(Mandatory=$True)]
        [string] $log_services_url_string,
        [Parameter(Mandatory=$True)]
        [Hashtable] $JsonHeader
    )

    # Get the response log server resource
    $response_log_services_url = Invoke-WebRequest -Uri $log_services_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
    $converted_object = $response_log_services_url.Content | ConvertFrom-Json
    $hash_table1 = @{}
    $converted_object.psobject.properties | ForEach-Object { $hash_table1[$_.Name] = $_.Value }

    foreach ($i in $hash_table1.Members)
    {
        $log_uri_address_string = "https://$ip" + $i.'@odata.id'

        $response_log_uri_address = Invoke-WebRequest -Uri $log_uri_address_string -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response_log_uri_address.Content | ConvertFrom-Json
        $hash_table2 = @{}
        $converted_object.psobject.properties | ForEach-Object { $hash_table2[$_.Name] = $_.Value }

        # Get the clear system log url
        if($hash_table2.Keys -contains "Actions")
        {
            $clear_log_url_string ="https://$ip" + $hash_table2.Actions.'#LogService.ClearLog'.'target'
        }
        else
        {
            continue
        }

        # Build request body and send requests to clear the system log
        $body = @{}
        if($converted_object.Actions.'#LogService.ClearLog'.'@Redfish.ActionInfo')
        {
           $url_actioninfo = "https://$ip"+$hash_table2.Actions.'#LogService.ClearLog'.'@Redfish.ActionInfo'
           $response = Invoke-WebRequest -Uri $url_actioninfo -Headers $JsonHeader -Method Get -UseBasicParsing
           $converted_object = $response.Content | ConvertFrom-Json
           foreach($parameter in $converted_object."Parameters")
           {
               if($parameter."Name" -and $parameter."AllowableValues")
               {
                   $values = $parameter."AllowableValues"
                   $body = @{$parameter."Name"=$values[0]}
               }
           }
        }else
        {
            $body = @{"Action"="LogService.ClearLog"}
        }
        $json_body = $body | convertto-json

        Write-Host
        [String]::Format("Clear system log under {0}...", $log_uri_address_string)

        # perform patch
        $response_clear_log = Invoke-WebRequest -Uri $clear_log_url_string -Headers $JsonHeader -Method Post  -Body $json_body -ContentType 'application/json'

        Write-Host
        [String]::Format("Statuscode {0} returned to successfully clear system log under {1}.",$response_clear_log.StatusCode, $log_uri_address_string)

    }
}
