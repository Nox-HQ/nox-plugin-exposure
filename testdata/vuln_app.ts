// EXPOSE-001: Exposed internal IP addresses
const internalDb: string = "10.10.0.5";
const gateway: string = "http://gateway.internal.corp/api";

// EXPOSE-002: Exposed email addresses
const contactEmail: string = "devops@company.com";

// EXPOSE-003: Exposed system paths
function getLogPath(): string {
    return "/var/log/application";
}

function getHostsFile(): string {
    return "/etc/hosts";
}

// EXPOSE-004: Exposed version information
const headers = {
    "Server: Nginx/1.22.0": true,
    version: "3.14.2",
};
