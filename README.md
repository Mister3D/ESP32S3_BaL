Voici le pinout du projet :
PIN_IN_BOUTON :        41
PIN_IN_PORTE_RUE :     40
PIN_IN_PORTE_TERRAIN : 17
PIN_IN_FENTE :         16
PIN_IN_CLE :           15
PIN_OUT_GACHE :        1
PIN_OUT_LUMIERE :      2

Les les pin in sont en pullup

Voici les fonctionnalité à mettre en place :
1) Crée deux constantes en début de code, DELAY_GACHE qui determine en mlliseconde combien de temps est déclenché la gache brancher sur PIN_OUT_GACHE, et DELAY_AWAIT_GACHE
2) Crée une fonction openDore() qui passe à l'état bas le pin PIN_OUT_GACHE puis bas apres le delais définit par DELAY_GACHE , sur le delais de DELAY_AWAIT_GACHE, il ne peut y avoir qu'un seul declenchement.
3) Si PIN_IN_CLE ou PIN_IN_BOUTON passe à l'état haut, il faut declencher openDore()
4) Quand PIN_IN_PORTE_TERRAIN ou PIN_IN_PORTE_RUE est ouvert, alors il faut alumer la lumiere sur PIN_OUT_LUMIERE
5) Quand PIN_IN_PORTE_RUE est actionner, il faut envoyer une notification via MQTT sur le canal "action" avec le payload { "location": "street", "action": "open" } ou { "location": "street", "action": "close" }
6) Quand PIN_IN_PORTE_TERRAIN est actionner, il faut envoyer une notification via MQTT avec le payload { "location": "house", "action": "open" } ou { "location": "house ", "action": "close" }
7) Quand PIN_IN_FENTE est actionner, il faut envoyer une notification via MQTT avec le payload { "location": "slot", "action": "open" } ou { "location": "slot ", "action": "close" }
8) Depuis MQTT il faut pouvoir ouvrire la porte
9) Affiche le status des pins et permet d'actionner la lumiere ou ouvrire la porte depuis l'interface web


Informations d'implémentation et d’utilisation
- Paramètres ajoutés:
  - `DELAY_GACHE` (par défaut 1200 ms): durée de l’impulsion de la gâche sur `PIN_OUT_GACHE`.
  - `DELAY_AWAIT_GACHE` (par défaut 5000 ms): anti-rafale; une seule impulsion possible durant ce délai.
  - Gestion du rollover de `millis()`: toutes les comparaisons temporelles utilisent une différence signée pour éviter les blocages après ~49 jours.

- Logique Gâche (PIN_OUT_GACHE):
  - Sortie « active bas ». L’impulsion met le pin à l’état bas pendant `DELAY_GACHE` puis le remet à l’état haut.
  - Déclenchement:
    - Front montant de `PIN_IN_BOUTON` ou `PIN_IN_CLE`.
    - Commande depuis l’UI (bouton « Ouvrir »).
    - Commande MQTT: publication sur `baseTopic/door/open` avec payload `1`, `true`, `open` ou `on`.
  - Anti-rafale: une impulsion max par fenêtre `DELAY_AWAIT_GACHE`.

- Logique Lumière (PIN_OUT_LUMIERE):
  - S’allume automatiquement si `PIN_IN_PORTE_RUE` ou `PIN_IN_PORTE_TERRAIN` est à l’état haut (portes ouvertes).
  - Peut être forcée depuis l’UI via un toggle (prioritaire sur l’auto tant qu’activé).

- Publication MQTT (évènements d’entrées):
  - Topic: `baseTopic/action`.
  - Payload JSON:
    - Porte rue: `{ "location": "street", "action": "open|close" }`.
    - Porte terrain: `{ "location": "house", "action": "open|close" }`.
    - Fente: `{ "location": "slot", "action": "open|close" }`.
  - Autres topics:
    - `baseTopic/status` (retained): `online`/`offline` (LWT).
    - `baseTopic/meta` (retained): `{ "version": "...", "build": "..." }` au (re)rattachement MQTT.
    - `baseTopic/uptime` (retained): secondes d’uptime publiées chaque seconde.

- Commandes MQTT:
  - `baseTopic/door/open` (subscribe): ouvre la porte si payload `1`, `true`, `open`, `on`.

- API HTTP (auth Bearer requise sauf mention contraire):
  - Non authentifié:
    - `GET /api/meta`: version/build.
    - `POST /api/login`: `{ "password": "..." }` → `{ "token": "..." }`.
  - Authentifié:
    - `GET /api/ping`: `{ "ok": true }`.
    - `GET /api/io`: états des entrées/sorties et flag `forceLight`.
    - `POST /api/door/open`: impulsion gâche.
    - `POST /api/debug/out`: `{ "pin": <num>, "value": true|false }` (autorisé: lumière en lecture/écriture, gâche en écriture « true » uniquement).
    - `GET/POST /api/network`: lecture/écriture configuration réseau (DHCP/IP statique).
    - `GET/POST /api/mqtt`: lecture/écriture configuration MQTT (`host`, `port`, `username`, `password`, `clientId`, `baseTopic`).
    - `POST /api/password`: changer le mot de passe `{ oldPassword, newPassword }`.
    - `POST /api/reboot`: redémarrage.
    - `POST /api/ota`: mise à jour firmware (binaire brut, sans multipart).

- Interface Web (embarqué):
  - Accès: ouvrir l’IP du module; mot de passe par défaut: `1234` (modifiable dans l’UI).
  - Debug I/O:
    - Entrées: badges « Ouverte/Fermée » (portes/fente) et « Actif/Inactif » (bouton/clé).
    - Sorties: état lisible + commandes dédiées:
      - Gâche: état « Active (impulsion)/Repos » + bouton « Ouvrir ».
      - Lumière: état « Allumée/Éteinte » + toggle de commande.

- Génération des assets Web:
  - Automatique via PlatformIO (`extra_scripts = pre:scripts/embed_web.py`).
  - Manuel possible: `python3 scripts/embed_web.py` (le script fonctionne aussi hors-PlatformIO).

- Réseau/Ethernet:
  - DHCP par défaut; configuration statique possible via `GET/POST /api/network` ou l’UI.
  - Carte: T-ETH-Lite avec W5500; l’adresse MAC Ethernet est dérivée de la MAC WiFi de l’ESP32.

- Rappels matériels:
  - Les entrées sont en pull-up.
  - `PIN_OUT_GACHE` est actif bas.