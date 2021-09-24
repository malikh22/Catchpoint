function RunTshark() {
    & 'C:\Program Files\Wireshark\tshark.exe' `
    -n `
    -l `
    -T ek `
    -e _ws.col.Protocol `
    -e ip.proto `
    -e ip.src `
    -e ip.dst `
    -e tcp.srcport `
    -e tcp.dstport `
    -e udp.srcport `
    -e udp.dstport `
    -f "(src net not (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)) and (tcp[0xd]&18=2 or udp)" `
    2>$null
}

function ProcessPacket($InPacketJson) {

    $InPacket = (ConvertFrom-Json $InPacketJson).layers

    if ($InPacket.ip_src) {
        if ($InPacket.tcp_srcport) {$SrcPort = $InPacket.tcp_srcport[0]} elseif ($InPacket.udp_srcport) {$SrcPort = $InPacket.udp_srcport[0]} else {$SrcPort = $null}
        if ($InPacket.tcp_dstport) {$DstPort = $InPacket.tcp_dstport[0]} elseif ($InPacket.udp_dstport) {$DstPort = $InPacket.udp_dstport[0]} else {$DstPort = $null}

        Switch ($InPacket.ip_proto) {
            1 { $Protocol = "ICMP"; break }
            6 { $Protocol = "TCP"; break }
            17 { $Protocol = "UDP"; break }
            default { $Protocol = $InPacket.ip_proto; break }
        }

        $Packet = New-Object -TypeName PSObject -Property @{
            SrcIP   = $InPacket.ip_src[0]
            DstIP   = $InPacket.ip_dst[0]
            Protocol = $Protocol
            SrcPort = $SrcPort
            DstPort = $DstPort
        }

        Write-Output $Packet | Select Protocol, SrcIP, SrcPort, DstIP, DstPort
    }
}