rule privilege_escalation_detection
{
    meta:
        description = "Detects privilege escalation using the 'sudo' command"
        author = "Daniel Wood"

    strings:
        $sudo_command = "sudo"

    condition:
        $sudo_command
}
