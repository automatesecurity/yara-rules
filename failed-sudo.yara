rule failed_sudo_attempt_detection
{
    meta:
        description = "Detects failed 'sudo' attempts"
        author = "Daniel Wood"

    strings:
        $sudo_attempt_string1 = "sudo: sorry, you must have a tty to run sudo"
        $sudo_attempt_string2 = "sudo: no tty present and no askpass program specified"
        $sudo_attempt_string3 = "sudo: authentication failure"
        $sudo_attempt_string4 = "sudo: 1 incorrect password attempt"

    condition:
        $sudo_attempt_string1 or $sudo_attempt_string2 or $sudo_attempt_string3 or $sudo_attempt_string4
}
