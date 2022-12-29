rule python_http_server_detection
{
    meta:
        description = "Detects a Python HTTP server"
        author = "Daniel Wood"

    strings:
        $http_server_string1 = "SimpleHTTPServer"
        $http_server_string2 = "http.server"

    condition:
        $http_server_string1 or $http_server_string2
}
