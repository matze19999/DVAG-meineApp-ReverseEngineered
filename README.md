# DVAG MeineApp Finanzdaten Export

Inoffizielles Python-Script zum Abrufen der Finanzübersicht aus dem DVAG Kundenportal bzw. der MeineApp-API.

Das Script meldet sich mit den eigenen Zugangsdaten an, registriert bei Bedarf eine AppId per SMS, speichert den Bearer Token lokal zwischen und gibt die JSON-Antwort der Finanzübersicht direkt im Terminal aus. Zusätzlich wird die Antwort in `finanzdaten_meine.json` gespeichert.

## Hinweis

Dieses Projekt ist nicht offiziell von DVAG, Vermögensberatung oder den Betreibern der MeineApp. Die verwendeten Endpunkte und Header wurden aus der Android-App bzw. dem beobachteten API-Verhalten abgeleitet.

Verwende das Script nur mit deinem eigenen Konto und nur, wenn du dazu berechtigt bist. Die ausgegebenen JSON-Dateien und der Token-Cache enthalten persönliche bzw. sensible Daten und gehören nicht in ein GitHub-Repository.

## Funktionen

- Login gegen den DVAG OpenID-Connect-Endpunkt
- automatische Nutzung eines gespeicherten Bearer Tokens
- Refresh des Tokens, wenn ein gültiger Refresh Token vorhanden ist
- AppId-Registrierung per SMS, falls der Server `invalid_appid` meldet
- Abruf der Finanzübersicht für `zuordnung=MEINE`
- direkte JSON-Ausgabe im Terminal
- Speicherung der JSON-Antwort in `finanzdaten_meine.json`

## Voraussetzungen

- Python 3.10 oder neuer
- Python-Paket `requests`
- gültiger DVAG / MeineApp Zugang
- Zugriff auf die hinterlegte Mobilnummer, falls eine AppId-Registrierung notwendig ist

Installation der Python-Abhängigkeit:

```bash
python3 -m pip install requests
```

## Nutzung

Script starten:

```bash
python3 main.py
```

Beim ersten Start fragt das Script nach Benutzername bzw. E-Mail und Passwort.

Wenn der Server eine registrierte AppId verlangt, erscheint eine Nachfrage:

```text
Der Server verlangt eine registrierte AppId für dieses Konto.
AppId jetzt per SMS registrieren? [j/N]:
```

Mit `j` startet der SMS-Prozess. Das Script ruft die für das Konto bekannten Mobilnummern ab, sendet einen SMS-Code an die ausgewählte Nummer und fragt den Code im Terminal ab.

Nach erfolgreicher Registrierung wird ein Bearer Token abgerufen. Die Finanzübersicht wird danach direkt als formatiertes JSON im Terminal ausgegeben und in `finanzdaten_meine.json` gespeichert.

## Token-Cache

Nach erfolgreichem Login speichert das Script die Token-Daten lokal in:

```text
meineapp_token_cache.json
```

Die Datei enthält unter anderem Access Token, Refresh Token, Benutzername und App-Secret. Sie wird mit Dateirechten `0600` angelegt, sollte aber trotzdem wie ein Passwort behandelt werden.

Bei späteren Aufrufen versucht das Script zuerst:

1. einen noch gültigen Access Token aus dem Cache zu verwenden
2. andernfalls den Access Token per Refresh Token zu erneuern
3. erst wenn das nicht möglich ist, erneut Benutzername und Passwort abzufragen

Cache löschen und Login erzwingen:

```bash
rm meineapp_token_cache.json
```

## Ausgabedateien

`finanzdaten_meine.json`

Enthält die zuletzt abgerufene Finanzübersicht für `zuordnung=MEINE`.

`meineapp_token_cache.json`

Enthält sensible Login- und Token-Daten.

Beide Dateien sollten nicht committed werden. Empfohlener `.gitignore`-Eintrag:

```gitignore
meineapp_token_cache.json
finanzdaten_meine.json
```

## API-Details

Das Script nutzt unter anderem:

- Basis-URL: `https://meinportal.dvag`
- Token-Endpunkt: `/auth/realms/DVAG/protocol/openid-connect/token`
- OAuth Client: `kundenportal`
- Setup Client für AppId-Registrierung: `setupkundenportal`
- Android Application ID: `com.dvag.meineapp`
- Finanzübersicht: `/vertrag/rest/v1/uebersichten`

Der Bearer Token wird im Header `Authorization: Bearer <token>` gesendet. Zusätzlich wird die Client-Version der Android-App übertragen.

## Typische Fehler

### `invalid_grant`

Der Server lehnt Benutzername oder Passwort ab. Prüfe die Zugangsdaten und ob der Account im offiziellen Portal bzw. in der App funktioniert.

### `invalid_appid`

Der Account verlangt eine registrierte AppId. Starte die SMS-Registrierung im Script mit `j`.

### `Token-Refresh fehlgeschlagen`

Der gespeicherte Refresh Token ist abgelaufen oder ungültig. Lösche `meineapp_token_cache.json` und melde dich neu an.

### `ModuleNotFoundError: No module named 'requests'`

Installiere die Abhängigkeit:

```bash
python3 -m pip install requests
```

### `Sicherheit`

Wer Zugriff auf den Token-Cache hat, kann unter Umständen API-Anfragen in deinem Namen ausführen, solange die Tokens gültig sind.
