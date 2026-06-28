export const INITIAL_CVES = [
  {
    id: "CVE-2024-3094",
    cve_id: "CVE-2024-3094",
    severity: "CRITICAL",
    cvss_score: 10.0,
    affected_technologies: ["xz-utils", "openssh"],
    description: "Malicious code was discovered in xz-utils versions 5.6.0 and 5.6.1. This backdoor allows an unauthorized remote attacker to bypass SSH authentication, gaining full access to the target host under specific conditions.",
    remediation: "Downgrade xz-utils to version 5.4.6 or upgrade immediately to distribution-patched releases (e.g., v5.6.1-2+ in Debian/Ubuntu). Restrict SSH access to trusted IPs.",
    published_at: "2024-03-29T18:00:00Z"
  },
  {
    id: "CVE-2021-44228",
    cve_id: "CVE-2021-44228",
    severity: "CRITICAL",
    cvss_score: 10.0,
    affected_technologies: ["log4j"],
    description: "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers.",
    remediation: "Upgrade Apache Log4j to version 2.15.0 or 2.16.0. Alternatively, set system property `log4j2.formatMsgNoLookups` to `true` or remove the JndiLookup class from the classpath.",
    published_at: "2021-12-10T08:00:00Z"
  },
  {
    id: "CVE-2024-21626",
    cve_id: "CVE-2024-21626",
    severity: "HIGH",
    cvss_score: 8.6,
    affected_technologies: ["docker", "runc", "kubernetes"],
    description: "runc 1.1.11 and earlier contains an internal file descriptor leak vulnerability. An attacker can exploit this by running a malicious container image, causing container escape and gaining full root access to the host operating system.",
    remediation: "Upgrade runc to version 1.1.12 or later. If container updates are not immediately possible, restrict container execution privileges and avoid running untrusted images.",
    published_at: "2024-01-31T22:15:00Z"
  },
  {
    id: "CVE-2022-22965",
    cve_id: "CVE-2022-22965",
    severity: "CRITICAL",
    cvss_score: 9.8,
    affected_technologies: ["spring-boot"],
    description: "Spring Framework (Spring4Shell) vulnerability allows remote code execution (RCE) via data binding. When running on JDK 9+ with Tomcat packaging, an attacker can manipulate class loaders to write arbitrary files (like webshells) to the server.",
    remediation: "Upgrade Spring Framework to version 5.3.18 or 5.2.20, or upgrade Spring Boot to 2.6.6 or 2.5.12.",
    published_at: "2022-04-01T06:15:00Z"
  },
  {
    id: "CVE-2023-38408",
    cve_id: "CVE-2023-38408",
    severity: "HIGH",
    cvss_score: 8.1,
    affected_technologies: ["openssh"],
    description: "A security flaw exists in OpenSSH's ssh-agent where remote code execution is possible via PKCS#11 agent forwarding if an attacker compromises a server where the agent is forwarded.",
    remediation: "Upgrade to OpenSSH 9.3p2 or newer. Disable agent forwarding (`ForwardAgent no` in ssh_config) unless strictly necessary.",
    published_at: "2023-07-19T14:00:00Z"
  },
  {
    id: "CVE-2023-4863",
    cve_id: "CVE-2023-4863",
    severity: "HIGH",
    cvss_score: 8.8,
    affected_technologies: ["chrome", "nginx", "apache"],
    description: "Heap buffer overflow in libwebp vulnerability in WebP image parsing. An attacker can construct a malicious WebP image that triggers heap-based memory corruption, potentially leading to arbitrary code execution when rendered by browsers or web servers using libwebp.",
    remediation: "Update libwebp to version 1.3.2 or later. Ensure system-level updates are applied for dependent browsers and server libraries.",
    published_at: "2023-09-12T15:00:00Z"
  },
  {
    id: "CVE-2023-34048",
    cve_id: "CVE-2023-34048",
    severity: "CRITICAL",
    cvss_score: 9.8,
    affected_technologies: ["vcenter"],
    description: "VMware vCenter Server contains an out-of-bounds write vulnerability in the implementation of the DCERPC protocol. A malicious actor with network access to vCenter Server may trigger an out-of-bounds write leading to remote code execution.",
    remediation: "Apply VMware patches KB95027 immediately. Restrict access to vCenter Server management ports (e.g., 2012/TCP) to authorized admin networks only.",
    published_at: "2023-10-24T17:30:00Z"
  },
  {
    id: "CVE-2024-23897",
    cve_id: "CVE-2024-23897",
    severity: "MEDIUM",
    cvss_score: 7.5,
    affected_technologies: ["jenkins"],
    description: "Jenkins contains an arbitrary file read vulnerability via its command-line interface (CLI) parser. An attacker can exploit this to read arbitrary files from the Jenkins controller file system, which can leak secrets and credentials.",
    remediation: "Upgrade Jenkins to version 2.442 or LTS 2.426.3. Alternatively, disable the CLI option if it is not in use.",
    published_at: "2024-01-24T16:15:00Z"
  }
];

export const INITIAL_CUSTOMERS = [
  {
    id: "cust-acme",
    username: "acme_security",
    company_name: "Acme Corporation",
    email: "security-team@acme.com",
    logo_initials: "AC",
    security_tier: "Standard Guard",
    tech_stack: ["nginx", "postgresql", "docker", "runc", "openssh"],
    notification_settings: {
      dashboard: true,
      email: true,
      slack: false,
      webhook: false
    }
  },
  {
    id: "cust-globaltech",
    username: "globaltech_ops",
    company_name: "GlobalTech Solutions",
    email: "devops@globaltech.io",
    logo_initials: "GT",
    security_tier: "Enhanced Guard",
    tech_stack: ["apache", "mysql", "php", "openssh", "nginx"],
    notification_settings: {
      dashboard: true,
      email: true,
      slack: true,
      webhook: false
    }
  },
  {
    id: "cust-securebank",
    username: "securebank_infosec",
    company_name: "SecureBank Inc.",
    email: "ciso-alerts@securebank.com",
    logo_initials: "SB",
    security_tier: "Critical Defense Plus",
    tech_stack: ["kubernetes", "spring-boot", "redis", "log4j", "vcenter", "docker", "runc"],
    notification_settings: {
      dashboard: true,
      email: true,
      slack: true,
      webhook: true
    }
  }
];

export const SYSTEM_SCRIPTS = [
  {
    name: "cve_nvd_crawler.py",
    description: "Crawls NVD feed API hourly for matching keywords.",
    status: "Active",
    last_run: "15 minutes ago",
    success_rate: "99.8%"
  },
  {
    name: "cve_github_advisories.py",
    description: "Parses new GitHub Security Advisory releases.",
    status: "Active",
    last_run: "45 minutes ago",
    success_rate: "100%"
  },
  {
    name: "vuln_alert_dispatcher.py",
    description: "Evaluates matching algorithms and updates dashboard feeds.",
    status: "Active",
    last_run: "Instant (On new CVE)",
    success_rate: "99.9%"
  }
];

export const INITIAL_ALERT_LOGS = [
  {
    id: "alert-1",
    customer_id: "cust-securebank",
    customer_name: "SecureBank Inc.",
    cve_id: "CVE-2024-3094",
    severity: "CRITICAL",
    technology: "openssh",
    status: "Dispatched",
    timestamp: "2024-03-29T18:05:00Z"
  },
  {
    id: "alert-2",
    customer_id: "cust-acme",
    customer_name: "Acme Corporation",
    cve_id: "CVE-2024-3094",
    severity: "CRITICAL",
    technology: "openssh",
    status: "Dispatched",
    timestamp: "2024-03-29T18:05:10Z"
  },
  {
    id: "alert-3",
    customer_id: "cust-securebank",
    customer_name: "SecureBank Inc.",
    cve_id: "CVE-2024-21626",
    severity: "HIGH",
    technology: "runc",
    status: "Dispatched",
    timestamp: "2024-01-31T22:20:00Z"
  },
  {
    id: "alert-4",
    customer_id: "cust-acme",
    customer_name: "Acme Corporation",
    cve_id: "CVE-2024-21626",
    severity: "HIGH",
    technology: "runc",
    status: "Dispatched",
    timestamp: "2024-01-31T22:21:00Z"
  }
];

// Helper to check if a technology matches stack (case-insensitive)
export const checkStackMatch = (tech, stack) => {
  return stack.some(s => s.toLowerCase() === tech.toLowerCase());
};
