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

```
incident-management-platform/
├── backend/      ASP.NET Core Web API (C#, EF Core)
├── frontend/     Angular SPA (TypeScript)
├── docs/         architecture, database, API and security design
├── docker/       container definitions (later phase)
└── .github/      CI/CD workflows (later phase)
```

## Documentation

Design is documented before implementation, and kept in sync with it:

- [Architecture](docs/architecture.md) — layering, project layout, middleware pipeline, cross-cutting decisions
- [Database Design](docs/database-design.md) — ERD, all tables, keys, indexes, and the reasoning behind the model
- [API Design](docs/api-design.md) — endpoint contracts, pagination/filtering/sorting conventions, error shape
- [Security](docs/security.md) — authentication, RBAC, OWASP-mapped controls, secure file handling, known gaps