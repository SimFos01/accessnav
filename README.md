# Access NAV App
## Example `.env`

```
DB_HOST=localhost
DB_USER=myuser
DB_PASS=secret
DB_NAME=kf_flow
JWT_SECRET=your_jwt_secret
PI_API_KEY=my_pi_internal_key
```

Dette er en Node.js-basert server for prototyping av adgangssystemet *Keyfree Flow*.

## Installasjon

1. Sørg for at du har **Node.js** installert (>= 14).
2. Klon dette repositoriet og installer avhengigheter:
   ```bash
   git clone <repo-url>
   cd accessnav
   npm install
   ```
3. Opprett en `.env`-fil i rotkatalogen og definer nødvendige miljøvariabler (se nedenfor).
4. Start serveren:
   ```bash
   node app.js
   ```
   Serveren lytter som standard på `http://localhost:3000`.

## Miljøvariabler

| Navn       | Beskrivelse                  |
|------------|------------------------------|
| `DB_HOST`  | Adresse til MariaDB-serveren |
| `DB_USER`  | Databasebruker               |
| `DB_PASS`  | Passord for databasebruker   |
| `DB_NAME`  | Databasenavn                 |
| `JWT_SECRET` | Hemmelig nøkkel brukt for å signere JWT-token |

Alle variablene må settes i `.env`-filen før du starter applikasjonen.

## Raspberry-adapter tidsavbrudd

Forespørsler mot Raspberry-låser vil automatisk time ut etter 4 sekunder. Hvis
låsen ikke svarer, gjør serveren ett nytt forsøk etter 3 sekunder. Dette
hindrer at brukergrensesnittet henger dersom en lås er utilgjengelig.

## Brukseksempler

Registrer en ny bruker:
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"hemmelig"}'
```

Logg inn og hent JWT-token:
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"hemmelig"}'
```

Kall en beskyttet rute (erstatt `<TOKEN>` med token fra forrige steg):
```bash
curl -H "Authorization: Bearer <TOKEN>" http://localhost:3000/me
```

Swagger-dokumentasjon er tilgjengelig på `http://localhost:3000/api-docs` etter at serveren er startet.
Et enkelt web-grensesnitt ligger i `public/webui/index.html`. Start serveren og åpne `http://localhost:3000/webui/index.html` i nettleseren for å logge inn, se og opprette låser samt administrere tilgangsgrupper.

## API-endepunkter

Nedenfor følger en kort oversikt over de viktigste API-kallene. De fleste krever at du sender med en gyldig JWT-token i `Authorization`-headeren ("Bearer `<TOKEN>`").

### Autentisering og generelle

| Metode | URL | Beskrivelse |
| ------ | --- | ----------- |
| `POST` | `/auth/register` | Opprett en ny bruker |
| `POST` | `/auth/login` | Logg inn og motta JWT |
| `GET` | `/me` | Eksempel på beskyttet rute |
| `GET` | `/health` | Helsetest av serveren |

### Brukerrelaterte

| Metode | URL | Beskrivelse |
| ------ | --- | ----------- |
| `POST` | `/user/login` | Autentiser bruker (alternativ innlogging) |
| `POST` | `/user/userlocks/shared-users` | Liste over brukere en lås er delt med |

### Låser

| Metode | URL | Beskrivelse |
| ------ | --- | ----------- |
| `POST` | `/lock` | Opprett ny lås |
| `GET` | `/lock` | Hent låser brukeren har tilgang til |
| `GET` | `/lock/:id/status` | Hent status for gitt lås |
| `POST` | `/lock/:id/open` | Åpne lås |
| `POST` | `/lock/:id/lock` | Lås lås |
| `POST` | `/lock/accessible` | Låser som eies av innlogget bruker |
| `POST` | `/lock/getbyid` | Hent detaljer for en lås via ID |
| `POST` | `/lock/all_accessible` | Alle låser brukeren kan åpne |
| `GET` | `/lock/:id/users` | Brukere med tilgang til en lås |

### Tilgangsgrupper

| Metode | URL | Beskrivelse |
| ------ | --- | ----------- |
| `POST` | `/accessgroup/list` | Tilgangsgrupper knyttet til innlogget bruker |
| `POST` | `/accessgroup/create` | Opprett ny tilgangsgruppe |
| `POST` | `/accessgroup/add-user` | Legg til bruker i gruppe |
| `POST` | `/accessgroup/add-lock` | Legg til lås i gruppe |
| `POST` | `/accessgroup/users` | Hent brukere i en tilgangsgruppe |

### Logger og profiler

| Metode | URL | Beskrivelse |
| ------ | --- | ----------- |
| `GET` | `/log` | Hent alle adgangslogger |
| `GET` | `/log/:lockId` | Logger for en spesifikk lås |
| `GET` | `/log/:lockId/last` | Siste aktivitet på lås |
| `POST` | `/profile/profile` | Profilinformasjon for innlogget bruker |


Denne applikasjonen bruker Node.js. Prosjektet inkluderer enkle enhetstester som kan kjøres med Node sitt innebygde test-rammeverk.

## Kjøre tester

Installer avhengigheter og kjør deretter:

```bash
npm test
```

Dette vil kjøre alle testfiler i `tests/`-mappen.
#
