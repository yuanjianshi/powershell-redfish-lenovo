###
#
# Lenovo Redfish examples - Mount virtual media from rdoc
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


function lenovo_mount_virtual_media_from_rdoc
{
    <#
   .Synopsis
    Cmdlet used to mount virtual media from rdoc
   .DESCRIPTION
    Cmdlet used to mount virtual media from rdoc from BMC using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - fsprotocol: Specifies the protocol for uploading image or ISO. For the SFTP/FTP protocol, the iso size must be <= 50MB. Support: ["Samba","NFS","HTTP","SFTP","FTP"]
    - fsip: Specify the file server ip
    - fsusername: Username to access the file path, available for Samba, NFS, HTTP/HTTPS, SFTP/FTP
    - fspassword: Password to access the file path, password should be encrypted after object creation, available for Samba, NFS, HTTP/HTTPS, SFTP/FTP
    - fsdir: File path of the image
    - isoname: Mount media iso name
    - readonly: It indicates the image is mapped as readonly or read/write. Support: [0:False, 1:True]
    - domain: Domain of the username to access the file path, available for Samba only
    - options: It indicates the mount options to map the image of the file path, available for Samba and NFS only
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_mount_virtual_media_from_rdoc -ip 10.10.10.10 -username USERID -password PASSW0RD -fsprotocol FSPROTOCOL -fsip FSIP -fsusername USERNAME -fspassword FSPASSWORD -fsdir FSDIR -isoname ISONAME
   #>
   
    param
    (
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$False)]
        [string]$config_file="config.ini",

        [Parameter(Mandatory=$False, HelpMessage='Support: ["Samba","NFS","HTTP","SFTP","FTP"]')]
        [string]$fsprotocol="",
        [Parameter(Mandatory=$False)]
        [string]$fsip="",
        [Parameter(Mandatory=$False)]
        [string]$fsusername="",
        [Parameter(Mandatory=$False)]
        [string]$fspassword="",
        [Parameter(Mandatory=$False)]
        [string]$fsdir="",
        [Parameter(Mandatory=$True)]
        [string]$isoname="",
        [Parameter(Mandatory=$False)]
        [int]$readonly=1,
        [Parameter(Mandatory=$False)]
        [string]$domain="",
        [Parameter(Mandatory=$False)]
        [string]$option=""    
    )
        
    # Get configuration info from config file
    $ht_config_ini_info = @{'BmcIp'=''; 'BmcUsername'=''; 'BmcUserpassword'=''; 'SystemId'='';'FSprotocol'='';'FSip'='';'FSpassword'='';'FSdir'=''}
    $payload = Get-Content -Path $config_file |
    Where-object {$_ -like '*=*'} |
    ForEach-Object {
        $infos = $_ -split '='
        $key = $infos[0].Trim()
        $value = $infos[1].Trim()
        $ht_config_ini_info[$key] = $value
    }

    
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
    if ($fsprotocol -eq "")
    {
        $fsprotocol = [string]($ht_config_ini_info['FSprotocol'])
    }
    if ($fsip -eq "")
    {
        $fsip = [string]($ht_config_ini_info['FSip'])
    }
    if ($fsusername -eq "")
    {
        $fsusername = [string]($ht_config_ini_info['FSusername'])
    }
    if ($fspassword -eq "")
    {
        $fspassword = [string]($ht_config_ini_info['FSpassword'])
    }
    if ($fsdir -eq "")
    {
        $fsdir = [string]($ht_config_ini_info['FSdir'])
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
            
            #Get mount media iso url
            $remotecontrol_url ="https://$ip"+$converted_object.Oem.Lenovo.RemoteControl.'@odata.id'
            $remotemap_url ="https://$ip"+$converted_object.Oem.Lenovo.RemoteMap.'@odata.id'
            
            $response = Invoke-WebRequest -Uri $remotecontrol_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json

            # Get MountImages url from remote control resource instance
            $upload_url = "https://$ip" + $converted_object.'Actions'.'#LenovoRemoteControlService.UploadFromURL'.'target'

            # Build request body for add images member
            $body = @{}
            $protocol = $fsprotocol.ToLower()
            if($protocol -eq "nfs")
            {
                $body["sourceURL"] = "nfs://" + $fsip + "/" + $fsdir + "/" + $isoname
            }
            elseif($protocol -eq "samba")
            {
                $body["sourceURL"] = "smb://" + $fsip + '/' + $fsdir + "/" + $isoname
            }
            elseif('sftp', 'ftp', 'http', 'https' -contains $protocol)
            {
                $body["sourceURL"] = $protocol + "://" + $fsip + '/' + $fsdir + "/" + $isoname
            }
            else
            {
                write-Host 'Mount media iso RDOC only support protocol Samba, NFS, HTTP/HTTPS, SFTP/FTP'
                return $False
            }

            $body["Type"] = $fsprotocol
            $body["Username"] = $fsusername
            $body["Password"] = $fspassword
            $body["Domain"] = $domain
            $body["Readonly"] = [bool]$readonly
            $body["Options"] = $option

            $JsonBody = $body | ConvertTo-Json -Compress

            # Add image member
            $response = Invoke-WebRequest -Uri $upload_url -Headers $JsonHeader -Method Post -Body $JsonBody -ContentType 'application/json' -UseBasicParsing
            if($response.statuscode -eq 200)
            {
                write-Host "Upload media iso successful, next will mount media iso..."
                $response = Invoke-WebRequest -Uri $remotemap_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $converted_object = $response.Content | ConvertFrom-Json
                $mount_image_url = "https://$ip" + $converted_object.'Actions'.'#LenovoRemoteMapService.Mount'.'target'

                # Mount virtual media from rdoc
                $response = Invoke-WebRequest -Uri $mount_image_url -Headers $JsonHeader -Method Post -UseBasicParsing
            }
            
            Write-Host
            [String]::Format("- PASS, statuscode {0} returned successfully to mount virtual media from network.", $response.StatusCode)
        }
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
        if ($session_key -ne "")
        {
            delete_session -ip $ip -session $session
        }
    }
}
