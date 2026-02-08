# SOC Incident Investigation – Crosscheck  
**Year-End Compensation & Performance Review Data Access**

---

## Executive Summary

During routine monitoring of year-end compensation and performance review activity, irregular access patterns were observed that initially resembled legitimate administrative behavior. Further investigation revealed a coordinated, multi-stage activity chain involving scripted execution, reconnaissance, sensitive data discovery, staging, persistence, outbound connectivity testing, and anti-forensic behavior.

This investigation was conducted **exclusively using KQL** and Microsoft Defender for Endpoint telemetry, requiring correlation across **multiple endpoints**, **user contexts**, and **telemetry tables**.

---

## Scope

**Primary Endpoint**
- sys1-dept

**Secondary Endpoint**
- main1-srvr

**Observed User / Session Contexts**
- 5y51-d3p7
- YE-HELPDESKTECH
- YE-HRPLANNER
- YE-FINANCEREVIE

---

## High-Level Attack Chain

1. Initial endpoint association using a non-standard local account  
2. PowerShell execution of a support-themed script from a user directory  
3. Host and identity reconnaissance  
4. Discovery of bonus and performance review artifacts  
5. Local staging of sensitive data into archives  
6. Persistence via Registry Run key and Scheduled Task  
7. Outbound connectivity testing and transfer attempts  
8. Anti-forensic log clearing  
9. Scope expansion to a second endpoint  
10. Repeat staging and outbound activity on second endpoint  

---

## Conclusion

This investigation demonstrates how legitimate-looking administrative workflows can be leveraged to mask a complete attack chain. Disciplined KQL-only analysis across Defender telemetry enabled full reconstruction of the chain from initial access to final outbound destination.

---

## Credits

Thanks to **Josh Madakor** and **Joshua Balondo** for designing and maintaining the cyber range environment that made this investigation possible.

---

## Disclaimer

This report is based on a controlled cyber range scenario. All systems, users, files, and IP addresses are simulated and do not represent real-world entities.
