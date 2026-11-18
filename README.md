# CTF_03122026 – Shadow Boarding
## Story
Several hours ago, **Eurodorf Airport** suffered a cyber incident known as
**"Phantom Flights."** Teams believed it was contained. Then, during boarding of
flight **ED472** (Eurodorf → Euroland), valid passengers were rejected at
scanning with different error codes. The SOC suspects the attack is ongoing.

You are an OSINT analyst. Everything below was collected from social media.

| Ch. | Name | Question |
|---|---|---|
| 1 | Instagram: First Symptom | When did the compromise begin? |
| 2 | Facebook: The Passengers | Which seats were affected? |
| 3 | The Contractor | What made the attack possible? |
| 4 | Man on the Path | How was it done, was the API hacked? |
| 5 | Off the Map | (Geolocation)

Each solved chapter gives a vault key that opens `chapterN/vault.json` with one
fragment of the boarding pass code.

---

## Chapter 1: Instagram – First Symptom
**Flag:** `FLAG{HH:MM:SS}` (24h, local time)

**Profile `@eurodorf.ground_ops`** (fan account of a ground-crew member, 412 posts)
```
Bio:  Ramp agent @ Eurodorf ✈  | gate A12 is my second home | #ED472 #PhantomFlights
Link: eurodorf-crew.example/linkinbio   (archived copy below)
```
Post 1 (08:15): selfie at gate A12. Tagged: `@m.kova_travels`
Post 2 (10:43): photo of the gate display. Caption: "Scanners dying again 🙄"
  Photo metadata (EXIF, as extracted):
```
DateTimeOriginal : 10:43:41     OffsetTimeOriginal : +01:00
Device           : Phone model X, clock set manually (see story)
```
Story highlight "Shift notes" (text on image):
> "Reminder: my phone clock runs **1 min 34 s fast**. Do not trust it."

Comment thread on Post 2:
> **@m.kovac_travels:** "got ERR 303 at 10:43 by the gate clock"
> **@dispatch_eurodorf:** "Gateway log shows first reject about 9 seconds
> after the redirect. Check the status page archive."

**Archived status page**
```
10:40:03  gateway: boarding validation OK (seat 18E)
10:42:07  gateway: first rejected scan (seat 32A, ERR 286)
10:43:30  gateway: rejected scan (seat 14F, ERR 303)
```
*Hint: the first visible symptom is not the start. Correct the clock, then look at the delay.*

---

## Chapter 2: Facebook – The Passengers
**Flag:** `FLAG{seat_seat_...}`
Format: every affected seat, **sorted by row number, then letter**, joined by `_`
(example shape: `1C_2B_3F_...`). Do not include seats that boarded fine.

**Public group "Eurodorf Frequent Flyers"** (3,204 members)

> **Marta Voinea** 🇷🇴: Seat 14F, ERR 303. Gate A12.
> **Dino Barbu** 🇷🇴: 22C here, code 401.
> **Sofia Marin** 🇷🇴: Screenshot of gate screen. I'm 3F.
> **Aleks Pop** 🇷🇴: 26F and 13D, different codes.
> **Neagu Stan** 🇷🇴: 32A, code 286.
> **Ana Tudor** 🇷🇴: My sister is 9D, I'm 12D, both rejected.
> **Bogdan Gheorghe** 🇷🇴: 27A and 24B, same gate.
> **Lena Dumitru** 🇷🇴: Friends trip: 5A, 2B, 1C, 8D, 11C, 11B.
> **Camille Laurent** 🇫🇷: Bonjour, siège 15D, le scanner dit erreur. On attend à la porte A12.
> **Lucas Moreau** 🇫🇷: Moi 19B. Même problème, code différent de ma femme.
> **Inès Dubois** 🇫🇷: 16A, refusée deux fois. Quelqu'un a un numéro de l'aéroport ?
> **Carlos Ruiz** 🇪🇸: Asiento 12F, el escáner no funciona. Llevamos 30 minutos aquí.
> **Lucía Fernández** 🇪🇸: Mi tarjeta es válida pero dice error. Asiento 29F.
> **Jake Miller** 🇺🇸: Anyone else stuck at A12? Scanner says error. I'm 28C.
> **Emily Carter** 🇺🇸: Boarding pass valid, scanner still says no. Seat 18E, flying with my dad.
> **Radu Ilie** 🇷🇴: I'm on 14E and boarded fine. Anyone else OK?

**Profiles (username pivoting)**

| Facebook profile | Public info |
|---|---|
| Paul P. (`Houghte`) | Part-time gate agent. Check-in photo alt text: "boarding pass, seat 9D" |
| Marinela S. (`Inden1943`) | Album "ED472": "me at 5A before takeoff" |
| Claudia I. (`Prembid`) | Event "Girls trip": "seat 2B" |
| Iasmina U. (`Meir1982`) | Pet: dog **Bella**, born 1982 |
| Neagu S. (`Wasereave`) | Mastodon: "CTF player. Travelling 32A." |
| `Cory1944` | Cessna fan page, mentions 29F |
| `Reate1955` | Spitfire collector, mentions 3F |
| `Doetianighim1961` | Blog link, mentions 24B |

**Email recovery:** emails follow the pattern shown in each profile's "About".
Only a mask and a hash are provided.
```
p****.p@example.com        SHA-256: <EMAIL_HASH_1>
m*****.s@example.com       SHA-256: <EMAIL_HASH_2>
n****.s@example.com        SHA-256: <EMAIL_HASH_3>
c*****.i@example.com       SHA-256: <EMAIL_HASH_4>
i*****.u@example.com       SHA-256: <EMAIL_HASH_5>
```

username            : hash                                      type
---------------------------------------------------------------------------
Houghte             : <HASH_1>                                  MD5
Wasereave           : <HASH_2>                                  SHA1
Inden1943           : <HASH_3>                                  MD5
Prembid             : <HASH_4>                                  SHA256
Meir1982            : <SALT>:<HASH_5>                           SHA256(salt+pass)
Cory1944            : <BCRYPT_HASH>                             bcrypt
Reate1955           : <SALT>:<HASH_6>                           SHA256(salt+pass)
Doetianighim1961    : <HASH_7>                                  MD5
admin_eurodorf      : <BCRYPT_HASH_ADMIN>                       bcrypt ("organizer backup")
```
*Hint: build your wordlist from names, pets, years and planes. Cracking a password
confirms which profile owns which seat. Some seats are not in any post.*

```

## Chapter 3: The Contractor
**Flag:** `FLAG{WEAKNESS_WEAKNESS_...}` (UPPERCASE, joined by `_`, in the order shown in the evidence)

Pivot: a Facebook comment by "Paul P." links to the contractor's public GitHub.
```
commit 2c10aa9   contractor <dev@example.com>   08:31   Remove debug files (.env.bak deleted)
commit 7b8e44d   contractor <dev@example.com>   08:50   Add service account
commit 9a3f1c2   contractor <dev@example.com>   09:12   Update config
```
`config.yml` (7b8e44d)
```yaml
service_user: svc_boardinq
api: https://api.eurodorf-gw.example/v1/boarding
tls_verify: false
xml_signature_check: false
dns: 10.0.0.53
```
`.env.bak` (2c10aa9, decoy)
```
API_KEY=sk_live_FAKE_000000000000
FLAG_VAULT_PASS=<DECOY_PASS>
```
Gateway error sample
```
svc_boardinq  TLS_CERT_MISMATCH         (ignored)
svc_boardinq  XML_SIGNATURE_NOT_VALIDATED
svc_boardinq  API_RESPONSE_ACCEPTED_WITHOUT_VALIDATION
```
*Hint: what did the client choose NOT to verify?*

---

## Chapter 4: Man on the Path
**Flag 4.1:** `FLAG{<STATUS>_<WHERE>}`  **Flag 4.2:** `FLAG{TECHNIQUE_NAME_Txxxx}`

Source: a Facebook post by the page "Eurodorf IT Notes" (10:41) and an Instagram
story by a "security researcher".
> "DNS answers can be rewritten. A client that doesn't verify certificates trusts anyone on the path."
```
```
*Hint: compare where the gateway connected before and after.*

---

## Chapter 5: Off the Map (Geolocation)

**Question:** The rogue DNS redirect was triggered from a public spot near the
airport. Where was the person standing when they posted their photo?
**Flag:** `FLAG{PLACENAME_STREETNAME}` (UPPERCASE, words joined by `_`,
no accents, e.g. `FLAG{CAFE_NORTH_MAIN_STREET}`)

**Pivot:** the Instagram account `@eurodorf.ground_ops` from Chapter 1 has a
tagged location-less post from 10:36 (before the incident).

**Post (photo attached: `chapter5/photo.jpg`, EXIF stripped)**
> "Quiet morning before boarding. Best coffee break spot 😎 #ED472 #PhantomFlights"

**Comment thread**
> **@m.kovac_travels:** "isn't that the place with the green tram stop right outside?"
> **@dispatch_eurodorf:** "Careful with posting. The gate is a 12 min walk from there."

**Facebook check-in** (group "Eurodorf Frequent Flyers", Neagu Stan)
> "Waiting for the shuttle, view of the river and the red bridge from here."

**Map hints (given as text, not coordinates)**
- Direction of the photo: roughly north-east
- The photo shows: a tram line, a red steel bridge, a building with a visible
  shop sign (partially legible), and a white church tower on the far bank
- Distance from the airport: within about 3 km (the airport itself is not named on any map)

**Steps (intended path)**
1. Identify the country and city from the tram, signage language and bridge.
2. Find the bridge in Google Maps (satellite view).
3. Use Street View along the river bank to match the angle, tower and shop sign.
4. Identify the exact public spot and its name.

*Hint: two bridges in the city look similar. Only one has the church tower
in line with the tram stop.*

