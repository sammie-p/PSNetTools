
$ticksTo1900 = [datetime]::new(1900, 1, 1,0,0,0,0,"Utc").Ticks

function Convert-DateTimeToNTPBytes([datetime]$DateTime) {
    $ticks = $DateTime.Ticks - $ticksTo1900 #ticks since 1901-01-01
    $bytes = [BitConverter]::GetBytes([uint64]([uint64]4294967296 * [decimal]0.0000001 * $ticks))
    if([System.BitConverter]::IsLittleEndian) {
        [array]::Reverse($bytes)
    }
    return $bytes
}

function Convert-NTPBytesToDateTime([byte[]]$Bytes) {
    $intPart = ([uint64] $Bytes[0] -shl 24) -bor ([uint64] $Bytes[1] -shl 16) -bor ([uint64] $Bytes[2] -shl 8) -bor $Bytes[3]
    $fractPart = ([uint64] $Bytes[4] -shl 24) -bor ([uint64] $Bytes[5] -shl 16) -bor ([uint64] $Bytes[6] -shl 8) -bor $Bytes[7]

	$ticks = ($intPart * 1000 + ($fractPart * 1000) / 0x100000000L) * [timespan]::TicksPerMillisecond
    return ([datetime]::new($ticks+$ticksTo1900, [System.DateTimeKind]::Utc))
}

if ((Get-TypeData 'NtpClientResult' -ea SilentlyContinue).DefaultDisplayPropertySet -eq $null) {
    Update-TypeData -TypeName 'NtpClientResult' -DefaultDisplayPropertySet 'Peer','ReferenceID','Stratum','Delay','Offset' -DefaultKeyPropertySet 'Offset','Delay'
}


function Get-NtpTime([parameter(ValueFromPipeline)][string[]]$ComputerName,[switch]$ExpandHosts,[switch]$ResolveNames) {
begin{
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $clock = get-date
}
process {
    foreach($Server in $ComputerName) {
        
        $ip = [ipaddress]::None
        if([ipaddress]::TryParse($Server,[ref]$ip)) {
            $ServerIPs = ,$ip
        } else {
            $ServerIPs = Resolve-DnsName -Name $Server -DnsOnly -Type A | select -First $(if($ExpandHosts){4}else{1}) -ExpandProperty IPAddress
        }


        foreach($ServerIP in $ServerIPs) {

            $ntpData = [byte[]]::new(48)
            $ntpData[0] = 0xE3 # leap unknown 3, version 4, client mode (3)
            $ntpData[2] = 0x0A #peer polling interval 10
            $ntpData[3] = 0xE9 #peer clock precision
    
            $ipEndPoint = [IPEndpoint]::new([ipaddress]$ServerIP, 123);
            $socket = [System.Net.Sockets.Socket]::new("InterNetwork", "Dgram", "Udp")
            $socket.ReceiveTimeout = 5000
            $socket.SendBufferSize = 48
            $socket.ReceiveBufferSize = 48
   
            try {
                $socket.Connect($ipEndPoint)
                $ntpData[40],$ntpData[41],$ntpData[42],$ntpData[43],$ntpData[44],$ntpData[45],$ntpData[46],$ntpData[47] = (Convert-DateTimeToNTPBytes -DateTime (get-date).ToUniversalTime())
            
                $BeginAcquireOffset = $sw.ElapsedTicks
                $socket.Send($ntpData) >> $null
                $socket.Receive($ntpData) >> $null
                $EndAcquireOffset = $sw.ElapsedTicks
            } catch {
                continue
            } finally {
                $socket.Close()
                $socket.Dispose()
            }

            $t2 = Convert-NTPBytesToDateTime -Bytes $ntpData[32..39]
            $t3 = Convert-NTPBytesToDateTime -Bytes $ntpData[40..47]
            $t1 = $clock.ToUniversalTime().AddTicks($BeginAcquireOffset)
            $t4 = $clock.ToUniversalTime().AddTicks($EndAcquireOffset)


            $offsetTicks = (($t2 - $t1) + ($t3 - $t4)).Ticks / 2


            $copy = $ntpData[4..7]
            if([System.BitConverter]::IsLittleEndian) {
                [array]::Reverse($copy)
            }
            $uint = [System.BitConverter]::ToUInt32($copy,0)
            $rootDelay = ([double]($uint -shr 16) + [double]($uint -band 0xFFFF) / [double]([long]1 -shl 16))*[timespan]::TicksPerSecond

            $copy = $ntpData[8..11]
            if([System.BitConverter]::IsLittleEndian) {
                [array]::Reverse($copy)
            }
            $uint = [System.BitConverter]::ToUInt32($copy,0)
            $rootDispersion = ([double]($uint -shr 16) + [double]($uint -band 0xFFFF) / [double]([long]1 -shl 16))*[timespan]::TicksPerSecond

            $precisionexp =  if($ntpData[3] -gt 127) { ([int16]($ntpData[3]))-256 } else { [int16]$ntpData[3] } 
            $pollexp =  if($ntpData[2] -gt 127) { ([int16]($ntpData[2]))-256 } else { [int16]$ntpData[2] } 

            if($ntpData[1] -eq 0 -or $ntpData[1] -ge 16) { #invalid, could be KoD packet
                $referenceID = $null
            } elseif ($ntpData[1] -eq 1) { #primary stratum
                $referenceID = [System.Text.Encoding]::ASCII.GetString($ntpData,12,4) -replace "\0.*","" #text replacing null char and successive chars with empty
            } else { #probably ipv4 address
                $referenceID = [ipaddress]::new($ntpData[12..15])
                if($ResolveNames) {
                    try {
                        $dns = $null
                        $dns = [string](Resolve-DnsName -Type PTR -Name $referenceID -ea SilentlyContinue -QuickTimeout | select -ExpandProperty NameHost -First 1)
                        if($dns -ne $null) {
                            $referenceID = $dns
                        }
                    } catch{}
                }
            }

   
            $NtpData=New-Object psobject -Property @{
                Peer=$ServerIP
                Leap = $ntpData[0] -shr 6
                Version = $ntpData[0] -shr 3 -band 5
                Mode = $ntpData[0] -band 5
                Stratum = $ntpData[1]
                PollExponent = $pollexp
                Poll = [timespan]::FromTicks([math]::Pow(2,$pollexp)*[timespan]::TicksPerSecond)
                PrecisionExponent = $precisionexp
                Precision = [timespan]::FromTicks([math]::Pow(2,$precisionexp)*[timespan]::TicksPerSecond)
                RootDelay = [timespan]::FromTicks($rootDelay)
                RootDispersion = [timespan]::FromTicks($rootDispersion)
                ReferenceID=$referenceID
                ReferenceTime = Convert-NTPBytesToDateTime -Bytes $ntpData[16..23]
                OriginateTime = Convert-NTPBytesToDateTime -Bytes $ntpData[24..31]
                ReceiveTime = $t2
                TransmitTime = $t3
                Delay = (($t4 - $t1) - ($t3 - $t2))
                Offset = [timespan]::FromTicks($offsetTicks)
            }

            if($ResolveNames) {
                try {
                    $dns = $null
                    $dns = [string](Resolve-DnsName -Type PTR -Name $ServerIP -ea SilentlyContinue -QuickTimeout | select -ExpandProperty NameHost -First 1)
                    if($dns -ne $null) {
                        $ntpData.Peer = $dns
                    }
                } catch{}
            }

            $ntpData.PSTypeNames.Insert(0,'NtpClientResult')

            #$ntpData | Add-Member MemberSet PSStandardMembers $PSStandardMembers
            $ntpData
        }
    } 
}
end {
    $sw.Stop()
}
}
