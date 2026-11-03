# PhishGuard Backend (Spring Boot 3 / Java 17)

Stage 2+3 of the PhishGuard project: JWT-authenticated REST API, MySQL
persistence, and the same detection engine the Chrome extension uses
locally — plus optional external threat-intel checks (Google Safe Browsing,
VirusTotal, AbuseIPDB, WHOIS domain age) that activate automatically the
moment you add an API key.

## ⚠️ Please read before you run this

I could not compile or run this project in the sandbox I built it in — my
network access there is limited to npm/PyPI/crates.io, not Maven Central, so
`mvn` can't resolve dependencies there. I've written it carefully and mirrored
the same logic that runs in the (verified, syntax-checked) extension, but you
should run `mvn clean install` and `mvn test` yourself as the real
verification step — don't take "complete" as "compiled." If something
doesn't build, tell me the error and I'll fix it directly.

## Quick start (zero setup — runs on in-memory H2)

```bash
cd phishguard-backend
mvn clean install
mvn spring-boot:run
```

The default profile uses an in-memory H2 database, so there's nothing to
install or configure to try it. On startup it seeds an admin account:
`admin@phishguard.local` / `ChangeMe123!` (change this immediately if you
ever deploy for real — override via `PHISHGUARD_ADMIN_EMAIL` /
`PHISHGUARD_ADMIN_PASSWORD` env vars).

- API: http://localhost:8009
- Swagger UI: http://localhost:8009/swagger-ui.html
- H2 console: http://localhost:8009/h2-console (JDBC URL `jdbc:h2:mem:phishguard`)

## Run against real MySQL

```bash
docker compose up --build
```

With Docker, the backend is reachable at **http://localhost:8090** (not
8009 — the host-side port was changed to avoid a conflict; the container's
own internal port is still 8009, this only affects how you reach it from
Windows). MySQL itself runs with username `phishguard` / password
`Keerthana`, exposed on the host at `localhost:3307` (also moved, to avoid
conflicting with a MySQL already running natively on this machine) if you
want to connect to it directly from Workbench or similar — the backend
container itself doesn't use that exposed port at all; it talks to MySQL
over Docker's own internal network.

Running natively instead of Docker:
```bash
mvn spring-boot:run -Dspring-boot.run.profiles=mysql \
  -DDB_HOST=localhost -DDB_USER=phishguard -DDB_PASSWORD=Keerthana
```
(Native, non-Docker MySQL still listens on the usual `3306` unless you've
configured it otherwise — Docker's `3307` mapping has no effect here.)

### ⚠️ If you've already tried this with a different password/config

**MySQL only runs its initial setup (creating the database and user) once,
the very first time its data volume is empty.** If a `phishguard-mysql-data`
volume already exists from an earlier attempt — including the plain
`docker run phishguard-backend` command from before this config was
corrected — MySQL will keep using whatever database/user/password was set
*that first time*, and will silently ignore any changes made to
`docker-compose.yml` afterward. This is the most likely reason "the
database isn't getting created" keeps happening even after a config fix.

**Fix: wipe the old volume and let MySQL reinitialize from scratch:**
```bash
docker compose down -v
docker compose up --build
```
`-v` removes the named volume along with the containers — this is safe to
run here since it's local development data, not production. Without `-v`,
`docker compose down` leaves the volume (and its stale credentials) intact.

### "The database isn't getting created" (other causes)

1. **The `mysql` profile was never actually activated.** Without
   `-Dspring-boot.run.profiles=mysql` (or `SPRING_PROFILES_ACTIVE=mysql` as
   an env var), Spring Boot silently falls back to the default profile —
   the in-memory H2 database — and starts up successfully with no error.
   The app *looks* like it's working, but MySQL is never touched at all.
   Check the startup log: it should say `The following 1 profile is
   active: "mysql"`. If it doesn't say that, the profile flag didn't reach
   the process.
2. **The `phishguard` schema doesn't exist yet, and the connecting user
   can't create it.** The JDBC URL includes `createDatabaseIfNotExist=true`,
   which auto-creates the schema on first connect — but only if the MySQL
   user has server-level `CREATE` privilege. `docker compose up` handles
   this automatically (the `phishguard` user is created with full rights on
   its own database). Connecting to a **local, manually-installed** MySQL
   server with a limited-privilege user, though, this will fail silently
   with an access-denied error buried in the stack trace. Fix: run this
   once via the MySQL CLI or Workbench using an admin account:
   ```sql
   CREATE DATABASE IF NOT EXISTS phishguard;
   GRANT ALL PRIVILEGES ON phishguard.* TO 'phishguard'@'%';
   FLUSH PRIVILEGES;
   ```

## Enabling external threat intel (all optional)

Set any of these env vars — each check activates independently and the
others keep working with no key at all:

| Env var | Provider | Free tier |
|---|---|---|
| `SAFE_BROWSING_API_KEY` | Google Safe Browsing v4 | Yes, via Google Cloud Console |
| `VIRUSTOTAL_API_KEY` | VirusTotal | Yes, community API key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | Yes, 1000 checks/day |
| `WHOIS_API_KEY` | WhoisXML API | Yes, limited free tier |

With none set, `/api/url/analyze` runs purely on the 9 local heuristic
checks (identical logic to the extension's `lib/detector.js`) — this is
exactly what Stage 1 already did standalone.

## API summary

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| POST | `/api/auth/register` | none | Create account |
| POST | `/api/auth/login` | none | Get JWT |
| POST | `/api/url/analyze` | none (optional) | **The extension calls this.** Scores a URL |
| GET | `/api/history?page=&size=` | JWT | Your own scan history, paginated |
| GET | `/api/admin/stats` | JWT + ROLE_ADMIN | Dashboard totals, most-targeted domains, latest threats |
| GET | `/api/admin/history?page=&size=` | JWT + ROLE_ADMIN | All users' scan history |

Full request/response schemas: see Swagger UI, or `docs/postman_collection.json`.

## Connecting the extension to this backend

In the extension's Options page, set **Backend base URL** to
`http://localhost:8009`. That's it — `background.js` already calls
`POST {backendUrl}/api/url/analyze` and falls back to local detection if
the backend is down, so nothing else in the extension needs to change.

## What's deliberately scoped out of this stage

- Redirect-chain crawling and live SSL certificate inspection (issuer,
  expiry) — both need to actually connect to the target site, which is a
  meaningfully different (and riskier) code path than the rest of this
  service; flagging this rather than quietly skipping it
- Refresh tokens (access token only, 1 hour expiry) — code is structured so
  adding a refresh-token endpoint is a small addition to `AuthService`
- Rate limiting, CSV/PDF export, and the charts/heatmap views — these live
  in the React admin frontend, described in `phishguard-frontend/README.md`
