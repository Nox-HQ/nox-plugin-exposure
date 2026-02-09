package main

import "fmt"

// EXPOSE-001: Exposed internal IP addresses and hostnames
var dbHost = "10.0.1.50"
var cacheHost = "192.168.1.100"
var internalAPI = "api.internal.corp"

// EXPOSE-002: Exposed email addresses
var adminEmail = "admin@company.com"
var supportEmail = "support@internal.corp"

// EXPOSE-003: Exposed system paths
func readConfig() {
	path := "/etc/passwd"
	logPath := "/var/log/syslog"
	fmt.Println(path, logPath)
}

// EXPOSE-004: Exposed version information
func serverHeader() string {
	return "Server: Apache/2.4.51"
}

func poweredBy() string {
	return "X-Powered-By: Express"
}
