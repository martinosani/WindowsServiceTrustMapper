# WindowsServiceTrustMapper

**WindowsServiceTrustMapper** is a PowerShell module designed to analyze Windows services from a security perspective by mapping **trust boundaries** between privileged services and user-controllable resources.

The tool focuses on identifying **risky service configurations** that can lead to **local privilege escalation (LPE)** and other security issues, without performing exploitation.

---

## Why this tool exists

Windows vulnerabilities can be caused by **incorrect trust assumptions**, such as:

- Privileged services executing code from unsafe paths
- Misconfigured file system permissions
- Scripted or indirect execution as SYSTEM
- Legacy or insecure service configurations

These issues are still frequently observed in real-world CVEs affecting third-party Windows software.

**WindowsServiceTrustMapper** helps surface these conditions early, in a structured and explainable way.

---

## What the tool does

For each Windows service, the tool analyzes:

- Service execution context (account, start mode, state)
- Service ImagePath and arguments
- Path parsing and quoting issues
- Executable resolution and existence
- File system permission risks (ACLs)
- Trust boundary violations

The output is a structured object with findings and a risk classification.

---

## What the tool does NOT do

- ❌ No exploitation
- ❌ No payload execution
- ❌ No vulnerability scanning signatures
- ❌ No persistence or system modification

This is an **analysis and reasoning tool**, not an exploit framework.

---

## Example use cases

- Security engineering and product security reviews
- Blue team / detection engineering
- Windows internals and OS security learning
- Pre-deployment security validation of third-party software
- Lab and research environments

---

## Installation (development / local use) and Usage

```powershell
Import-Module .\src\WindowsServiceTrustMapper.psd1 -Force
Get-WstmServiceTrustMap | Format-Table -AutoSize
```
