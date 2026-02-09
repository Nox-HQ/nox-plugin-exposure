// EXPOSE-001: Exposed internal IP addresses and hostnames
const dbConnection = "postgresql://user:pass@192.168.0.10:5432/mydb";
const apiEndpoint = "http://billing.internal.corp/v2/invoices";

// EXPOSE-002: Exposed email addresses
const notifyEmail = "alerts@company.com";
const adminContact = "sysadmin@internal.corp";

// EXPOSE-003: Exposed system paths
function readPasswords() {
    const path = "/etc/passwd";
    const winPath = "C:\\Users\\Administrator";
    console.log(path, winPath);
}

// EXPOSE-004: Exposed version information
function setHeaders(res) {
    res.setHeader("Server: IIS/10.0");
    res.setHeader("X-Powered-By", "Node.js");
}
