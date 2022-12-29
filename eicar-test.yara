rule eicar_detection
{
    meta:
        description = "Detects the EICAR test file"
        author = "Daniel Wood"

    strings:
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar_string
}
