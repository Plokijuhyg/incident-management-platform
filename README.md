# Cybersecurity Incident Management Platform

A full-stack platform for managing security incidents from detection through investigation, response, and resolution — built as a portfolio project with production-oriented architecture.

## Tech Stack

- **Backend:** C# / ASP.NET Core Web API (.NET 10 LTS), Entity Framework Core
- **Frontend:** Angular (TypeScript)
- **Database:** MySQL 8
- **Auth:** JWT Bearer Authentication, Role-Based Access Control (Admin / Security Manager / SOC Analyst)
- **DevOps:** Docker, GitHub Actions (planned)

## Scope

This is an incident management platform — not a SIEM replacement. It models the incident lifecycle (New → Triaged → Investigating → Contained → Eradicated → Recovering → Resolved → Closed), IOC tracking, MITRE ATT&CK mapping, evidence handling, and audit logging, and is designed to later integrate with external SIEM/EDR/IDS sources.

## Status

🚧 Under active development — see commit history for progress.

## Project Structure