rule reverse_shell_detection
{
    meta:
        description = "Detects a reverse shell"
        author = "Daniel Wood"

    strings:
        $reverse_shell_string1 = "nc -e"
        $reverse_shell_string2 = "bash -i >& /dev/tcp/"
        $reverse_shell_string3 = "0>&1"

    condition:
        $reverse_shell_string1 or $reverse_shell_string2 or $reverse_shell_string3
}
