###
#
# Lenovo Redfish examples - Set ldap information
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


function lenovo_set_ldap_server
{
   <#
   .Synopsis
    Cmdlet used to set ldap server
   .DESCRIPTION
    Cmdlet used to set ldap server using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - method: The LDAP servers to be used for authentication can either be manually configured or discovered dynamically via DNS SRV records. Support:["Pre_Configured","DNS"]
    - ldapserver: If you choose the pre-configured option, at least one server must be configured, you can configure up to 4 LDAP servers by entering each server IP address or hostname (assuming DNS is enabled)
    - port: The port number for each server is optional. If left blank, the default value of 389 is used for non-secured LDAP connections. For secured connections, the default is 636
    - domainname: This is only active under using DNS to find LDAP servers. If you choose to discover the LDAP servers dynamically, you will need to specify the search domain to be used
    - binding_method: This parameter controls how this initial bind to the LDAP server is performed, default Anonymously.Support:["Anonymously", "Configured", "Login"]
                      Parameter explain: "Anonymously": Bind without a DN or password. 
                                         "Configured": Bind with a DN and password. 
                                         "Login": Bind with the credentials supplied during the login process.
    - clientdn: Specify the Client Distinguished Name(DN) to be used for the initial bind. Note that LDAP Binding Method must be set to "Configured"
    - clientpwd: Note that LDAP Binding Method must be set to "Configured"
    - rootdn: BMC uses the "ROOT DN" field in Distinguished Name format as root entry of directory tree.This DN will be used as the base object for all searches.
    - uid_search_attribute: This search request must specify the attribute name used to represent user IDs on that server.
                            On Active Directory servers, this attribute name is usually sAMAccountName
                            On Novell eDirectory and OpenLDAP servers, it is usually uid
                            On Novell eDirectory and OpenLDAP servers, it is usually uid
    - role_base_security: This parameter to enable(1) or disable(0) enhanced role-based security for Active Directory Users
    - servername: This parameter configure the BMC LDAP server Target Name setting. Note that Enhanced role-based security for Active Directory Users must be enabled for this setting to take effect
    - group_filter: This field is used for group authentication, limited to 511 characters, and consists of one or more group names
                    Note that Enhanced role-based security for Active Directory Users must be disabled for this setting to take effect. If this field is left blank, it will default to memberof
    - group_search_attribute: This field is used by the search algorithm to find group membership infomation for a specific user
                              Note that Enhanced role-based security for Active Directory Users must be disabled for this setting to take effect
    - login_permission_attribute: When a user successfully authenticates via a LDAP server, it is necessary to retrieve the login permissions for this user
   .EXAMPLE
    lenovo_set_ldap_server -ip 10.10.10.10 -username USERID -password PASSW0RD -method METHOD -ldapserver @(LDAPSERVER, LDAPSERVER,...)
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$False)]
        [string]$method="",
        [Parameter(Mandatory=$False)]
        [array]$ldapserver=@(),
        [Parameter(Mandatory=$False)]
        [array]$port=@('389','389','389','389'),
        [Parameter(Mandatory=$False)]
        [string]$domainname="",
        [Parameter(Mandatory=$False)]
        [string]$binding_method="Anonymously",
        [Parameter(Mandatory=$False)]
        [string]$clientdn="",
        [Parameter(Mandatory=$False)]
        [string]$clientpwd="",
        [Parameter(Mandatory=$False)]
        [string]$rootdn="",
        [Parameter(Mandatory=$False)]
        [string]$uid_search_attribute="",
        [Parameter(Mandatory=$False)]
        [int]$role_base_security=0,
        [Parameter(Mandatory=$False)]
        [string]$servername="",
        [Parameter(Mandatory=$False)]
        [string]$group_filter="",
        [Parameter(Mandatory=$False)]
        [string]$group_search_attribute='memberof',
        [Parameter(Mandatory=$False)]
        [string]$login_permission_attribute="",
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
        
            # Get network url from the Manager resource instance
            $uri_address_manager = "https://$ip"+$manager_url_string
            $response = Invoke-WebRequest -Uri $uri_address_manager -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            
            $uri_network ="https://$ip"+$converted_object.NetworkProtocol.'@odata.id'
            $response = Invoke-WebRequest -Uri $uri_network -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            
            # Get the ldap client url form the network resource instance
            $ldap_client_uri = "https://$ip" + $converted_object.Oem.Lenovo.LDAPClient.'@odata.id'
            
            # Build request body for set ldap server
            $body = @{}
            $body['BindingMethod']=@{'ClientPassword'=$clientpwd;'ClientDN'=$clientdn;'Method'=$binding_method}
            $body['ActiveDirectory'] = @{'ServerTargetName'=$servername; 'RoleBasedSecurity'=[bool]$role_base_security}
            $body['RootDN'] = $rootdn
            $body['LoginPermissionAttribute'] = $login_permission_attribute
            $body['GroupFilter'] = $group_filter
            $body['GroupFilter'] = $group_search_attribute
            $body['GroupFilter'] = $uid_search_attribute

            $server_info = @{}
            $server_info["Method"] = $method
            if($method -eq 'Pre_Configured')
            {
                $count = 0
                foreach($x in $ldapserver)
                {
                    $server_info['Server' + [string]($count+1) + 'HostName_IPAddress'] = $ldapserver[$count]
                    $server_info['Server' + [string]($count+1) + 'Port'] = $port[$count]
                    $count += 1
                }
            }
            else
            {
                $server_info['SearchDomain'] = $domainname
            }

            $body['LDAPServers'] = $server_info
            $JsonBody = $body | ConvertTo-Json -Compress

            $response = Invoke-WebRequest -Uri $ldap_client_uri -Headers $JsonHeader -Method Patch -Body $JsonBody -ContentType 'application/json' -UseBasicParsing
            Write-Host
            [String]::Format("- PASS, statuscode {0} returned successfully to set ldap server.",$response.StatusCode)
            return $True
        }
    }
    catch
    {
        if($_.Exception.Response)
        {
            Write-Host "Error occured, error code:" $_.Exception.Response.StatusCode.Value__
            if ($_.Exception.Response.StatusCode.Value__ -eq 401)
            {
                Write-Host "Error message: You are required to log on Web Server with valid credentials first."
            }
            if ($_.ErrorDetails.Message)
            {
                $response_j = $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand error
                $response_j = $response_j | Select-Object -Expand '@Message.ExtendedInfo'
                Write-Host "Error message:" $response_j.Resolution
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