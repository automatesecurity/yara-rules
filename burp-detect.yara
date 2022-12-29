rule burp_suite_proxy_detection
{
    meta:
        description = "Detects the use of the Burp Suite proxy"
        author = "Daniel Wood"

    strings:
        $burp_suite_string1 = "Burp Suite Professional"
        $burp_suite_string2 = "burp"

    condition:
        $burp_suite_string1 or $burp_suite_string2
}
