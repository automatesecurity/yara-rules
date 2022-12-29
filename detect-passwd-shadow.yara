rule password_file_detection
{
    meta:
        description = "Detects attempts to view or modify the 'etc/passwd' or 'etc/shadow' files"
        author = "Your Name"

    strings:
        $passwd_file = "etc/passwd"
        $shadow_file = "etc/shadow"

    condition:
        $passwd_file or $shadow_file
}
