rule vpn_detection
{
    meta:
        description = "Detects VPN use"
        author = "Daniel Wood"

    strings:
        $vpn_string1 = "vpn"
        $vpn_string2 = "openvpn"
        $vpn_string3 = "pptp"
        $vpn_string4 = "l2tp"

    condition:
        $vpn_string1 or $vpn_string2 or $vpn_string3 or $vpn_string4
}
