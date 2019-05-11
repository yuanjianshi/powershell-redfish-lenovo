###
#
# Lenovo Redfish examples - Set BMC IPv4
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


function lenovo_set_bmc_ipv4
{
    <#
   .Synopsis
    Cmdlet used to set BMC IPv4
   .DESCRIPTION
    Cmdlet used to set BMC IPv4 from BMC using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - method: Specify the IPv4 configuration methods, Support:["DHCP", "Static", "DHCPFirstThenStatic"]
    - ipv4address: The value of this property shall be an IPv4 address assigned to this interface
    - netmask: The value of this property shall be the IPv4 subnet mask for this address
    - geteway: The value of this property shall be the IPv4 default gateway address for this interface
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_set_bmc_ipv4 -ip 10.10.10.10 -username USERID -password PASSW0RD -method METHOD -ipv4address IPV4ADDRESS -netmask NETMASK -geteway GETEWAY
   #>
   
    param
    (
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [ValidateSet("DHCP", "Static", "DHCPFirstThenStatic")]
        [Parameter(Mandatory=$True)]
        [string]$method="",
        [Parameter(Mandatory=$False)]
        [string]$ipv4address="",
        [Parameter(Mandatory=$False)]
        [string]$netmask="",
        [Parameter(Mandatory=$False)]
        [string]$geteway="",

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
    
        # Get the manager url collection
        $manager_url_collection = @()
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json

        
        $managers_url = $converted_object.Managers."@odata.id"
        $managers_url_string = "https://$ip" + $managers_url
        $response = Invoke-WebRequest -Uri $managers_url_string -Headers $JsonHeader -Method Get -UseBasicParsing 
       
        # Convert response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        
        # Set the $manager_url_collection
        foreach ($i in $hash_table.Members)
        {
            $i = [string]$i
            $manager_url_string = ($i.Split("=")[1].Replace("}",""))
            $manager_url_collection += $manager_url_string
        }

        # Loop all Manager resource instance in $manager_url_collection
        foreach ($manager_url_string in $manager_url_collection)
        {
            $uri_address_manager = "https://$ip"+$manager_url_string
            $response = Invoke-WebRequest -Uri $uri_address_manager -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            
            #Get Ethernet Interfaces uri
            $interfaces_url ="https://$ip"+$converted_object.EthernetInterfaces.'@odata.id'
            $response = Invoke-WebRequest -Uri $interfaces_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json

            # Get the interface member list
            $member_list = $converted_object.Members
            foreach ($i in $member_list)
            {
                $member_url = "https://$ip" + $i.'@odata.id'
                $member_array = $member_url.Split("/")
                $allow_method = @("Static", "DHCPFirstThenStatic")
                if($member_array -contains "NIC")
                {
                    $response = Invoke-WebRequest -Uri $member_url -Headers $JsonHeader -Method Get -UseBasicParsing
                    $converted_object = $response.Content | ConvertFrom-Json
                    $ipv4_address = $converted_object.IPv4Addresses
                    if($ipv4_address.Count -eq 1)
                    {
                        $ipv4_address[0] = @{"Address"=$ipv4address; "SubnetMask"=$netmask; "Gateway"=$gateway; "AddressOrigin"=$method}
                    }
                    else
                    {
                        if($allow_method -contains $method)
                        {
                            if($ipv4address -eq '' -or $netmask -eq '' -or $geteway -eq '')
                            {
                                Write-Host "When the method is static or DHCPFirstThenStatic, the user needs to specify ipv4address, netmask and gateway"
                                return $False
                            }
                            $ipv4_address[0] = @{"Address"=$ipv4address; "SubnetMask"=$netmask; "Gateway"=$gateway; "AddressOrigin"=$method}
                        }
                        elseif($method -eq "DHCP")
                        {
                            $ipv4_address[1] = @{"AddressOrigin"=$method}
                        }
                        else
                        {
                            Write-Host "Please check the IPv4 configuration methods is correct, only support 'Static', 'DHCP' or 'DHCPFirstThenStatic'."
                            return $False
                        }
                    }

                    # Modified the ethernet configuration through patch request
                    $body = @{"IPv4Addresses"=$ipv4_address; "Oem"=@{"Lenovo"=@{"IPv4AddressAssignedby"=$method}}}
                    $JsonBody = $body | ConvertTo-Json -Compress
                    
                    $response = Invoke-WebRequest -Uri $member_url -Headers $JsonHeader -Method patch -Body $JsonBody -ContentType 'application/json' -UseBasicParsing
                    [String]::Format("- PASS, statuscode {0} returned successfully to set BMC IPv4",$response.StatusCode)
                    return $True
                }    
            }
        }
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
