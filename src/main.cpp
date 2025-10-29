#include <Arduino.h>
#include <SPI.h>
#include <Ethernet.h>
#include <PubSubClient.h>
#include "web_assets.h"
#include <Preferences.h>
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include <esp_system.h>
#include <Update.h>

// Définir une structure pour représenter un périphérique avec un nom et un numéro de pin
struct Device {
    const char* name;
    int pin;
};


// --------------------- Projet BaL: Définition des broches et délais ---------------------
#define PIN_IN_BOUTON          41
#define PIN_IN_PORTE_RUE       40
#define PIN_IN_PORTE_TERRAIN   17
#define PIN_IN_FENTE           16
#define PIN_IN_CLE             15
#define PIN_OUT_GACHE          1
#define PIN_OUT_LUMIERE        2

// Les entrées sont en pull-up (actives selon câblage). Les règles ci-dessous
// considèrent qu'un état HAUT signifie « actif/ouvert » tel que décrit dans le README.

// Délais (ms)
#define DELAY_GACHE          1200
#define DELAY_AWAIT_GACHE    5000

// État runtime
static volatile unsigned long g_gacheActiveUntilMs = 0;
static volatile unsigned long g_gacheCooldownUntilMs = 0;
static bool g_forceLight = false; // Commande manuelle lumière via API/UI
static volatile bool g_rebootRequested = false;
static volatile unsigned long g_rebootAtMs = 0;

// Mémorisation niveaux précédents pour détection d'edges
static int g_prevBouton = -1;
static int g_prevCle = -1;
static int g_prevRue = -1;
static int g_prevTerrain = -1;
static int g_prevFente = -1;

// Prototype pour permettre l'appel depuis d'autres fonctions avant sa définition
static void openDore();


#define DEFAULT_PASSWORD "1234"
// Numéro de version du firmware
#define FW_VERSION "0.0.2"
// Identifiant de build accessible partout (utilisé par MQTT et /api/meta)
#define K_BUILD_ID (__DATE__ " " __TIME__)

// Définir ces paramètres pour la connexion statique
/*
#define NETWORK_IP "192.168.0.100"
#define NETWORK_MASK "255.255.255.0"
#define NETWORK_GATEWAY "192.168.0.1"
*/

#define LILYGO_T_ETH_W5500

#define ETH_MISO_PIN                    11
#define ETH_MOSI_PIN                    12
#define ETH_SCLK_PIN                    10
#define ETH_CS_PIN                      9
#define ETH_INT_PIN                     13
#define ETH_RST_PIN                     14
#define ETH_ADDR                        1

// Compatibilité : le cœur ESP32 définit Server::begin(uint16_t). Or la classe
// EthernetServer de la bibliothèque Ethernet n’implémente begin() qu’avec aucun paramètre.
// Cet adaptateur ajoute la signature manquante pour satisfaire à l’exigence de la méthode virtuelle pure.
class ESP32EthernetServerFix : public EthernetServer {
public:
    ESP32EthernetServerFix(uint16_t port) : EthernetServer(port) {}
    void begin(uint16_t port = 0) override { EthernetServer::begin(); }
};

EthernetClient ethClient;
PubSubClient mqttClient(ethClient);
ESP32EthernetServerFix httpServer(80);

// ---------- MQTT settings placés avant callback pour visibilité ----------
struct MqttSettings {
    String host;
    uint16_t port;
    String username;
    String password;
    String clientId;
    String baseTopic; // ex: "device"
};
static Preferences mqttNvs;
static MqttSettings g_mqtt;

// Variables for periodic publishing (heartbeat)
unsigned long lastMsg = 0;
const long interval = 1000;   // 1 second

 

void callback(char *topic, uint8_t *payload,  unsigned int length)
{
    String msg;
    msg.reserve(length + 1);
    for (unsigned int i = 0; i < length; i++) msg += (char)payload[i];
    msg.trim();
    String t = String(topic);
    Serial.print("MQTT in ["); Serial.print(t); Serial.print("] "); Serial.println(msg);
    // Commande d'ouverture depuis MQTT: baseTopic + "/door/open"
    String cmdOpen = g_mqtt.baseTopic + "/door/open";
    if (t == cmdOpen) {
        String low = msg; low.toLowerCase();
        if (low == "1" || low == "true" || low == "open" || low == "on") {
            openDore();
        }
        return;
    }
}

// (déclaration déjà déplacée au-dessus de callback)

static void loadMqttSettings()
{
    // Valeurs par défaut au premier démarrage
    if (g_mqtt.host.length() == 0 && g_mqtt.clientId.length() == 0 && g_mqtt.baseTopic.length() == 0) {
        g_mqtt.host = "";
        g_mqtt.port = 1883;
        g_mqtt.username = "";
        g_mqtt.password = "";
        g_mqtt.clientId = "esp32eth";
        g_mqtt.baseTopic = "device";
    }
    // Lecture NVS en lecture seule
    if (mqttNvs.begin("mqtt", true)) {
        String host = mqttNvs.getString("host", g_mqtt.host);
        uint16_t port = (uint16_t)mqttNvs.getUShort("port", g_mqtt.port);
        String user = mqttNvs.getString("user", g_mqtt.username);
        String pass = mqttNvs.getString("pass", g_mqtt.password);
        String cid  = mqttNvs.getString("cid",  g_mqtt.clientId);
        String base = mqttNvs.getString("base", g_mqtt.baseTopic);
        mqttNvs.end();
        g_mqtt.host = host;
        g_mqtt.port = port;
        g_mqtt.username = user;
        g_mqtt.password = pass;
        g_mqtt.clientId = cid;
        g_mqtt.baseTopic = base;
        Serial.print("MQTT loaded: host="); Serial.print(g_mqtt.host);
        Serial.print(" port="); Serial.print(g_mqtt.port);
        Serial.print(" user="); Serial.print(g_mqtt.username);
        Serial.print(" base="); Serial.println(g_mqtt.baseTopic);
    } else {
        Serial.println("MQTT NVS begin failed (read)");
    }
}

static void saveMqttSettings(const MqttSettings &s)
{
    if (!mqttNvs.begin("mqtt", false)) {
        Serial.println("MQTT NVS begin failed (write)");
        return;
    }
    mqttNvs.putString("host", s.host);
    mqttNvs.putUShort("port", s.port);
    mqttNvs.putString("user", s.username);
    mqttNvs.putString("pass", s.password);
    mqttNvs.putString("cid", s.clientId);
    mqttNvs.putString("base", s.baseTopic);
    mqttNvs.end();
    Serial.println("MQTT settings saved to NVS");
}

static void ensureMqttConnected()
{
    if (g_mqtt.host.length() == 0) return; // MQTT désactivé tant que non configuré
    if (!mqttClient.connected()) {
        mqttClient.setServer(g_mqtt.host.c_str(), g_mqtt.port);
    }
    if (mqttClient.connected()) return;
    static unsigned long lastAttempt = 0;
    static unsigned long backoffMs = 200;
    unsigned long now = millis();
    if (now - lastAttempt < backoffMs) {
        return;
    }
    lastAttempt = now;
    Serial.println("MQTT reconnecting...");
    String lwt = g_mqtt.baseTopic + "/status";
    bool ok = false;
    if (g_mqtt.username.length() > 0) {
        ok = mqttClient.connect(g_mqtt.clientId.c_str(), g_mqtt.username.c_str(), g_mqtt.password.c_str(), lwt.c_str(), 1, true, "offline");
    } else {
        ok = mqttClient.connect(g_mqtt.clientId.c_str(), nullptr, nullptr, lwt.c_str(), 1, true, "offline");
    }
    if (ok) {
        Serial.println("MQTT reconnected");
        backoffMs = 200;
        // Online status retained
        String on = "online";
        mqttClient.publish(lwt.c_str(), on.c_str(), true);
        // Publish meta once
        String metaJson = String("{\"version\":\"") + FW_VERSION + "\",\"build\":\"" + K_BUILD_ID + "\"}";
        String metaTopic = g_mqtt.baseTopic + "/meta";
        mqttClient.publish(metaTopic.c_str(), metaJson.c_str(), true);
        // S'abonner aux commandes
        String cmdOpen = g_mqtt.baseTopic + "/door/open";
        mqttClient.subscribe(cmdOpen.c_str());
        return;
    }
    if (backoffMs < 5000) backoffMs = backoffMs * 2;
}

static const web_asset_t *findAsset(const String &path)
{
    // Exact match on stored url
    for (uint32_t i = 0; i < WEB_ASSETS_COUNT; ++i) {
        if (path == WEB_ASSETS[i].url) {
            return &WEB_ASSETS[i];
        }
    }
    return nullptr;
}

static void sendHttpHeader(EthernetClient &client, int status, const char *statusText, const char *mime, uint32_t contentLength, bool gzip, bool cacheAllowed = true)
{
    client.print("HTTP/1.1 ");
    client.print(status);
    client.print(' ');
    client.println(statusText);
    client.print("Content-Type: ");
    client.println(mime);
    if (gzip) {
        client.println("Content-Encoding: gzip");
    }
    client.println("Connection: close");
    if (cacheAllowed) {
        client.println("Cache-Control: max-age=3600, public");
    } else {
        client.println("Cache-Control: no-store, no-cache, must-revalidate");
        client.println("Pragma: no-cache");
        client.println("Expires: 0");
    }
    client.print("Content-Length: ");
    client.println(contentLength);
    client.println();
}

static void writeAll(EthernetClient &client, const uint8_t *data, uint32_t len)
{
    const uint32_t maxChunk = 1024; // éviter de saturer le buffer TCP
    uint32_t written = 0;
    unsigned long lastProgress = millis();
    while (written < len && client.connected()) {
        int canWrite = client.availableForWrite();
        if (canWrite > 0) {
            uint32_t chunk = (uint32_t)canWrite;
            if (chunk > maxChunk) chunk = maxChunk;
            if (chunk > (len - written)) chunk = len - written;
            size_t w = client.write(data + written, chunk);
            if (w > 0) {
                written += (uint32_t)w;
                lastProgress = millis();
                continue;
            }
        }
        // pas de progrès: courte cession CPU, timeout après ~8s
        if (millis() - lastProgress > 8000) break;
        yield();
    }
    client.flush();
}

static String mapToExistingIndex()
{
    // Prefer common locations
    const char *candidates[] = { "/html/index.html", "/index.html", "/index.htm" };
    for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); ++i) {
        const web_asset_t *a = findAsset(String(candidates[i]));
        if (a != nullptr) return String(candidates[i]);
    }
    // Fallback: first HTML asset if any
    for (uint32_t i = 0; i < WEB_ASSETS_COUNT; ++i) {
        String mime = WEB_ASSETS[i].mime;
        if (mime.startsWith("text/html")) return String(WEB_ASSETS[i].url);
    }
    return String("");
}

// ---------- Auth & JWT ----------
static Preferences nvs;
static String g_password;

static void loadPassword()
{
    if (!nvs.begin("auth", false)) {
        g_password = DEFAULT_PASSWORD;
        return;
    }
    String saved = nvs.getString("pwd", "");
    if (saved.length() == 0) {
        g_password = DEFAULT_PASSWORD;
        nvs.putString("pwd", g_password);
    } else {
        g_password = saved;
    }
}

static bool savePassword(const String &newPwd)
{
    // Write using the same namespace opened in setup()
    if (newPwd == g_password) return true;
    size_t written = nvs.putString("pwd", newPwd);
    if (written == 0) {
        // Tentative d'ouverture du namespace si nécessaire puis nouvel essai
        if (nvs.begin("auth", false)) {
            written = nvs.putString("pwd", newPwd);
        }
    }
    if (written == 0) {
        // Certains backends peuvent retourner 0 si valeur identique ou pas d'
        // écriture physique. Vérifions par lecture.
        String check = nvs.getString("pwd", "");
        if (check == newPwd) {
            g_password = newPwd;
            return true;
        }
        return false;
    }
    g_password = newPwd;
    return true;
}

// ---------- Meta / Build detection ----------
static Preferences meta;

static void handleFirstBootOfBuild() {
    if (!meta.begin("meta", false)) {
        // Si impossible d'ouvrir, on ne fait rien pour ne pas bloquer
        return;
    }
    String last = meta.getString("buildId", "");
    if (last != String(K_BUILD_ID)) {
        Serial.println("Nouveau firmware flashé: réinitialise uniquement le mot de passe");

        if(nvs.begin("auth", false)) {
            size_t written = nvs.putString("pwd", DEFAULT_PASSWORD);
            if (written == 0) {
                // Vérifie par lecture si la valeur est bien prise en compte
                String check = nvs.getString("pwd", "");
                if (check == DEFAULT_PASSWORD) {
                    g_password = DEFAULT_PASSWORD;
                }
            } else {
                g_password = DEFAULT_PASSWORD;
            }
        }

        // Efface les paramètres réseau pour que la nouvelle build reparte sur défauts
        Preferences tmpNet;
        if (tmpNet.begin("net", false)) {
            tmpNet.clear();
        }
        meta.putString("buildId", K_BUILD_ID);
    }
}

// ---------- Configuration (NVS 'cfg') ----------
static Preferences cfg;

// ---------- Réseau (NVS 'net') ----------
static Preferences net;

struct NetSettings {
    bool useDhcp;
    IPAddress ip;
    IPAddress mask;
    IPAddress gw;
    IPAddress dns;
    bool loaded; // indique si une config a été chargée depuis NVS
};

static NetSettings g_net;

static void loadNetworkSettings()
{
    g_net.useDhcp = true;
    g_net.loaded = false;
    if (!net.begin("net", false)) {
        return;
    }
    bool dhcp = net.getBool("dhcp", true);
    if (dhcp) {
        g_net.useDhcp = true;
        g_net.loaded = true;
        return;
    }
    String ipS   = net.getString("ip", "");
    String maskS = net.getString("mask", "");
    String gwS   = net.getString("gw", "");
    String dnsS  = net.getString("dns", "");
    IPAddress ip, mask, gw, dns;
    bool okIp = ip.fromString(ipS);
    bool okMask = mask.fromString(maskS);
    bool okGw = gw.fromString(gwS);
    bool okDns = dns.fromString(dnsS);
    if (!okDns && okGw) dns = gw;
    if (okIp && okMask && okGw) {
        g_net.useDhcp = false;
        g_net.ip = ip;
        g_net.mask = mask;
        g_net.gw = gw;
        g_net.dns = okDns ? dns : gw;
        g_net.loaded = true;
    }
}

static void applyNetworkWithFallback(uint8_t mac[6])
{
    // 1) Priorité à la NVS 'net' si présente
    loadNetworkSettings();
    if (g_net.loaded) {
        if (g_net.useDhcp) {
            Serial.println("Waiting for link/DHCP (NVS)...");
            while (Ethernet.begin(mac) == 0) {
                if (Ethernet.linkStatus() == LinkOFF) {
                    Serial.println("... link down");
                } else {
                    Serial.println("... DHCP failed, retrying");
                }
                unsigned long waitStart = millis();
                while (millis() - waitStart < 1000UL) {
                    yield();
                }
            }
        } else {
            Ethernet.begin(mac, g_net.ip, g_net.dns, g_net.gw, g_net.mask);
            Serial.print("Static IP (NVS): ");
            Serial.println(g_net.ip);
        }
        return;
    }

    // 2) Sinon, fallback constantes de build si définies et valides
#if defined(NETWORK_IP) && defined(NETWORK_MASK) && defined(NETWORK_GATEWAY)
    {
        IPAddress ip, mask, gw, dns;
        bool okIp = ip.fromString(NETWORK_IP);
        bool okMask = mask.fromString(NETWORK_MASK);
        bool okGw = gw.fromString(NETWORK_GATEWAY);
        if (okIp && okMask && okGw) {
            dns = gw; // défaut
            Ethernet.begin(mac, ip, dns, gw, mask);
            Serial.print("Static IP (build): ");
            Serial.println(ip);
            return;
        }
    }
#endif

    // 3) Sinon DHCP
    while (Ethernet.begin(mac) == 0) {
        if (Ethernet.linkStatus() == LinkOFF) {
            Serial.println("... link down");
        } else {
            Serial.println("... DHCP failed, retrying");
        }
        unsigned long waitStart = millis();
        while (millis() - waitStart < 1000UL) {
            yield();
        }
    }
}



static String base64UrlEncode(const uint8_t *data, size_t len)
{
    // Standard base64 encode using mbedTLS, then convert to base64url
    size_t outLen = 0;
    // First, query length
    mbedtls_base64_encode(nullptr, 0, &outLen, data, len);
    String out;
    out.reserve(outLen + 4);
    uint8_t *buf = (uint8_t*)malloc(outLen + 4);
    if (!buf) return String("");
    if (mbedtls_base64_encode(buf, outLen + 4, &outLen, data, len) != 0) {
        free(buf);
        return String("");
    }
    for (size_t i = 0; i < outLen; ++i) {
        char c = (char)buf[i];
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
        else if (c == '=') continue; // skip padding
        out += c;
    }
    free(buf);
    return out;
}

static bool hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *msg, size_t msgLen, uint8_t out[32])
{
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, info, 1) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }
    if (mbedtls_md_hmac_starts(&ctx, key, keyLen) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }
    mbedtls_md_hmac_update(&ctx, msg, msgLen);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
    return true;
}

static String jwtCreateToken(const String &secret)
{
    // Minimal JWT with HS256; iat only (no real RTC available)
    String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    unsigned long iat = millis() / 1000UL;
    String payload = String("{\"iat\":") + String(iat) + "}";
    String hB64 = base64UrlEncode((const uint8_t*)header.c_str(), header.length());
    String pB64 = base64UrlEncode((const uint8_t*)payload.c_str(), payload.length());
    String base = hB64 + "." + pB64;
    uint8_t sig[32];
    if (!hmacSha256((const uint8_t*)secret.c_str(), secret.length(), (const uint8_t*)base.c_str(), base.length(), sig)) {
        return String("");
    }
    String sB64 = base64UrlEncode(sig, sizeof(sig));
    return base + "." + sB64;
}

static bool jwtVerifyToken(const String &token, const String &secret)
{
    int p1 = token.indexOf('.');
    if (p1 < 0) return false;
    int p2 = token.indexOf('.', p1 + 1);
    if (p2 < 0) return false;
    String base = token.substring(0, p2);
    uint8_t sig[32];
    if (!hmacSha256((const uint8_t*)secret.c_str(), secret.length(), (const uint8_t*)base.c_str(), base.length(), sig)) {
        return false;
    }
    String expected = base64UrlEncode(sig, sizeof(sig));
    String provided = token.substring(p2 + 1);
    return provided == expected;
}

// ---------- Simple HTTP parsing ----------
struct HeaderKV {
    String name;
    String value;
};

struct HttpHeaders {
    HeaderKV items[16];
    int count = 0;
    String get(const String &key) const {
        for (int i = 0; i < count; ++i) {
            if (items[i].name.equalsIgnoreCase(key)) return items[i].value;
        }
        return String("");
    }
};

static void sendJson(EthernetClient &client, int code, const char *status, const String &body, bool noCache = true)
{
    sendHttpHeader(client, code, status, "application/json; charset=utf-8", body.length(), false, !noCache);
    client.print(body);
}

static bool isAuthorized(const HttpHeaders &headers)
{
    String auth = headers.get("Authorization");
    if (auth.length() == 0) return false;
    if (!auth.startsWith("Bearer ")) return false;
    String tok = auth.substring(7);
    return jwtVerifyToken(tok, g_password);
}

static void handleApi(EthernetClient &client, const String &path)
{
    // Placeholder: legacy route kept for compile if called without new signature
    const char *body = "{\"error\":\"bad handler usage\"}";
    sendHttpHeader(client, 500, "Internal Server Error", "application/json; charset=utf-8", strlen(body), false, false);
    client.print(body);
    return;

}

static void handleApiEx(EthernetClient &client, const String &fullPath, const String &method, const HttpHeaders &headers, const String &bodyIn)
{
    // Meta (non authentifié): expose version et identifiant de build
    if (fullPath.startsWith("/api/meta")) {
        String resp = String("{\"version\":\"") + FW_VERSION + "\",\"build\":\"" + K_BUILD_ID + "\"}";
        sendJson(client, 200, "OK", resp, true);
        return;
    }

    if (fullPath.startsWith("/api/login")) {
        if (method != "POST") {
            String resp = "{\"error\":\"method not allowed\"}";
            sendJson(client, 405, "Method Not Allowed", resp);
            return;
        }
        // parse {"password":"..."}
        String pass;
        int pi = bodyIn.indexOf("\"password\"");
        if (pi >= 0) {
            int co = bodyIn.indexOf(':', pi);
            int q1 = bodyIn.indexOf('"', co + 1);
            int q2 = bodyIn.indexOf('"', q1 + 1);
            if (co >= 0 && q1 >= 0 && q2 > q1) pass = bodyIn.substring(q1 + 1, q2);
        }
        if (pass != g_password) {
            String resp = "{\"error\":\"invalid credentials\"}";
            sendJson(client, 401, "Unauthorized", resp);
            return;
        }
        String token = jwtCreateToken(g_password);
        String resp = String("{\"token\":\"") + token + "\"}";
        sendJson(client, 200, "OK", resp);
        return;
    }

    if (!isAuthorized(headers)) {
        String resp = "{\"error\":\"unauthorized\"}";
        sendJson(client, 401, "Unauthorized", resp);
        return;
    }

    if (fullPath.startsWith("/api/ping")) {
        String resp = "{\"ok\":true}";
        sendJson(client, 200, "OK", resp);
        return;
    }

    // ---------- I/O (auth requis) ----------
    if (fullPath.startsWith("/api/io")) {
        if (!isAuthorized(headers)) {
            String resp = "{\"error\":\"unauthorized\"}";
            sendJson(client, 401, "Unauthorized", resp);
            return;
        }
        if (method == "GET") {
            int vBouton = digitalRead(PIN_IN_BOUTON);
            int vCle = digitalRead(PIN_IN_CLE);
            int vRue = digitalRead(PIN_IN_PORTE_RUE);
            int vTerrain = digitalRead(PIN_IN_PORTE_TERRAIN);
            int vFente = digitalRead(PIN_IN_FENTE);
            int vGache = digitalRead(PIN_OUT_GACHE);
            int vLight = digitalRead(PIN_OUT_LUMIERE);
            String resp;
            resp.reserve(256);
            resp += "{";
            resp += "\"ins\":[";
            resp += "{\"name\":\"PIN_IN_BOUTON\",\"pin\":" + String(PIN_IN_BOUTON) + ",\"value\":" + String(vBouton) + "},";
            resp += "{\"name\":\"PIN_IN_CLE\",\"pin\":" + String(PIN_IN_CLE) + ",\"value\":" + String(vCle) + "},";
            resp += "{\"name\":\"PIN_IN_PORTE_RUE\",\"pin\":" + String(PIN_IN_PORTE_RUE) + ",\"value\":" + String(vRue) + "},";
            resp += "{\"name\":\"PIN_IN_PORTE_TERRAIN\",\"pin\":" + String(PIN_IN_PORTE_TERRAIN) + ",\"value\":" + String(vTerrain) + "},";
            resp += "{\"name\":\"PIN_IN_FENTE\",\"pin\":" + String(PIN_IN_FENTE) + ",\"value\":" + String(vFente) + "}";
            resp += "],";
            resp += "\"outs\":[";
            resp += "{\"name\":\"PIN_OUT_GACHE\",\"pin\":" + String(PIN_OUT_GACHE) + ",\"value\":" + String(vGache) + "},";
            resp += "{\"name\":\"PIN_OUT_LUMIERE\",\"pin\":" + String(PIN_OUT_LUMIERE) + ",\"value\":" + String(vLight) + "}";
            resp += "],";
            resp += "\"forceLight\":";
            resp += (g_forceLight ? "true" : "false");
            resp += "}";
            sendJson(client, 200, "OK", resp);
            return;
        }
        String resp = "{\"error\":\"method not allowed\"}";
        sendJson(client, 405, "Method Not Allowed", resp);
        return;
    }

    if (fullPath.startsWith("/api/debug/out")) {
        if (!isAuthorized(headers)) {
            String resp = "{\"error\":\"unauthorized\"}";
            sendJson(client, 401, "Unauthorized", resp);
            return;
        }
        if (method != "POST") {
            String resp = "{\"error\":\"method not allowed\"}";
            sendJson(client, 405, "Method Not Allowed", resp);
            return;
        }
        auto findInt = [&](const char* key, long defv) -> long {
            String k = String("\"") + key + "\"";
            int i = bodyIn.indexOf(k);
            if (i < 0) return defv;
            int co = bodyIn.indexOf(':', i);
            if (co < 0) return defv;
            int end = bodyIn.indexOf(',', co + 1);
            int end2 = bodyIn.indexOf('}', co + 1);
            if (end < 0 || (end2 >= 0 && end2 < end)) end = end2;
            String num = bodyIn.substring(co + 1, end);
            num.trim();
            return num.toInt();
        };
        auto findBool = [&](const char* key, bool defv) -> bool {
            String k = String("\"") + key + "\"";
            int i = bodyIn.indexOf(k);
            if (i < 0) return defv;
            int co = bodyIn.indexOf(':', i);
            if (co < 0) return defv;
            String v = bodyIn.substring(co + 1);
            v.trim();
            return v.startsWith("true") || v.startsWith("1");
        };
        long pin = findInt("pin", -1);
        bool value = findBool("value", false);
        if (pin == PIN_OUT_LUMIERE) {
            g_forceLight = value;
            digitalWrite(PIN_OUT_LUMIERE, value ? HIGH : LOW);
            String ok = "{\"ok\":true}";
            sendJson(client, 200, "OK", ok);
            return;
        }
        if (pin == PIN_OUT_GACHE && value) {
            openDore();
            String ok = "{\"ok\":true}";
            sendJson(client, 200, "OK", ok);
            return;
        }
        String resp = "{\"error\":\"pin not allowed\"}";
        sendJson(client, 400, "Bad Request", resp);
        return;
    }

    if (fullPath.startsWith("/api/door/open")) {
        if (!isAuthorized(headers)) {
            String resp = "{\"error\":\"unauthorized\"}";
            sendJson(client, 401, "Unauthorized", resp);
            return;
        }
        if (method != "POST") {
            String resp = "{\"error\":\"method not allowed\"}";
            sendJson(client, 405, "Method Not Allowed", resp);
            return;
        }
        openDore();
        String ok = "{\"opened\":true}";
        sendJson(client, 200, "OK", ok);
        return;
    }

    // ---------- Réseau ----------
    if (fullPath.startsWith("/api/network")) {
        if (method == "GET") {
            loadNetworkSettings();
            String resp = String("{\"dhcp\":") + (g_net.useDhcp ? "true" : "false") +
                          ",\"ip\":\"" + (g_net.loaded && !g_net.useDhcp ? g_net.ip.toString() : "") +
                          "\",\"mask\":\"" + (g_net.loaded && !g_net.useDhcp ? g_net.mask.toString() : "") +
                          "\",\"gw\":\"" + (g_net.loaded && !g_net.useDhcp ? g_net.gw.toString() : "") +
                          "\",\"dns\":\"" + (g_net.loaded && !g_net.useDhcp ? g_net.dns.toString() : "") +
                          "\"}";
            sendJson(client, 200, "OK", resp);
            return;
        }
        if (method == "POST") {
            auto findBool = [&](const char* key, bool defv) -> bool {
                String k = String("\"") + key + "\"";
                int i = bodyIn.indexOf(k);
                if (i < 0) return defv;
                int co = bodyIn.indexOf(':', i);
                if (co < 0) return defv;
                String v = bodyIn.substring(co + 1);
                v.trim();
                return v.startsWith("true");
            };
            auto findStr = [&](const char* key) -> String {
                String k = String("\"") + key + "\"";
                int i = bodyIn.indexOf(k);
                if (i < 0) return String("");
                int co = bodyIn.indexOf(':', i);
                int q1 = bodyIn.indexOf('"', co + 1);
                int q2 = bodyIn.indexOf('"', q1 + 1);
                if (co >= 0 && q1 >= 0 && q2 > q1) return bodyIn.substring(q1 + 1, q2);
                return String("");
            };
            bool dhcp = findBool("dhcp", true);
            if (!net.begin("net", false)) {
                String resp = "{\"error\":\"nvs open failed\"}";
                sendJson(client, 500, "Internal Server Error", resp);
                return;
            }
            net.putBool("dhcp", dhcp);
            if (!dhcp) {
                String ipS = findStr("ip");
                String maskS = findStr("mask");
                String gwS = findStr("gw");
                String dnsS = findStr("dns");
                net.putString("ip", ipS);
                net.putString("mask", maskS);
                net.putString("gw", gwS);
                net.putString("dns", dnsS);
            }
            String resp = "{\"saved\":true}";
            sendJson(client, 200, "OK", resp);
            return;
        }
        String resp = "{\"error\":\"method not allowed\"}";
        sendJson(client, 405, "Method Not Allowed", resp);
        return;
    }

    // ---------- MQTT ----------
    if (fullPath.startsWith("/api/mqtt")) {
        if (method == "GET") {
            loadMqttSettings();
            String resp = String("{\"host\":\"") + g_mqtt.host +
                          "\",\"port\":" + String(g_mqtt.port) +
                          ",\"username\":\"" + g_mqtt.username +
                          "\",\"password\":\"" + g_mqtt.password +
                          "\",\"clientId\":\"" + g_mqtt.clientId +
                          "\",\"baseTopic\":\"" + g_mqtt.baseTopic +
                          "\"}";
            sendJson(client, 200, "OK", resp);
            return;
        }
        if (method == "POST") {
            auto findStr = [&](const char* key, const String& defv = String("")) -> String {
                String k = String("\"") + key + "\"";
                int i = bodyIn.indexOf(k);
                if (i < 0) return defv;
                int co = bodyIn.indexOf(':', i);
                int q1 = bodyIn.indexOf('"', co + 1);
                int q2 = bodyIn.indexOf('"', q1 + 1);
                if (co >= 0 && q1 >= 0 && q2 > q1) return bodyIn.substring(q1 + 1, q2);
                return defv;
            };
            auto findInt = [&](const char* key, long defv) -> long {
                String k = String("\"") + key + "\"";
                int i = bodyIn.indexOf(k);
                if (i < 0) return defv;
                int co = bodyIn.indexOf(':', i);
                if (co < 0) return defv;
                int end = bodyIn.indexOf(',', co + 1);
                int end2 = bodyIn.indexOf('}', co + 1);
                if (end < 0 || (end2 >= 0 && end2 < end)) end = end2;
                String num = bodyIn.substring(co + 1, end);
                num.trim();
                return num.toInt();
            };
            // Copie actuelle pour comparaison
            MqttSettings before = g_mqtt;
            MqttSettings s = g_mqtt;
            s.host = findStr("host", s.host);
            s.port = (uint16_t)findInt("port", s.port);
            s.username = findStr("username", s.username);
            String pass = findStr("password");
            if (pass.length() > 0 || bodyIn.indexOf("\"password\"") >= 0) {
                s.password = pass; // autorise vide pour effacer
            }
            s.clientId = findStr("clientId", s.clientId);
            s.baseTopic = findStr("baseTopic", s.baseTopic);
            // Détecte changements
            bool changed = (s.host != before.host) || (s.port != before.port) ||
                           (s.username != before.username) || (s.password != before.password) ||
                           (s.clientId != before.clientId) || (s.baseTopic != before.baseTopic);
            // Sauvegarde systématique, puis reboot si changé
            saveMqttSettings(s);
            g_mqtt = s;
            mqttClient.disconnect();
            String resp = String("{\"saved\":true,\"rebooting\":") + (changed ? "true" : "false") + "}";
            sendJson(client, 200, "OK", resp);
            if (changed) {
                // Planifie un redémarrage rapide pour appliquer proprement la config
                g_rebootRequested = true;
                g_rebootAtMs = millis() + 500UL;
            }
            return;
        }
        String resp = "{\"error\":\"method not allowed\"}";
        sendJson(client, 405, "Method Not Allowed", resp);
        return;
    }

    // ---------- Reboot ----------
    if (fullPath.startsWith("/api/reboot")) {
        if (method != "POST") {
            String resp = "{\"error\":\"method not allowed\"}";
            sendJson(client, 405, "Method Not Allowed", resp);
            return;
        }
        String ok = "{\"rebooting\":true}";
        sendJson(client, 200, "OK", ok);
        client.flush();
        {
            unsigned long t0 = millis();
            while (millis() - t0 < 200UL) yield();
        }
        ESP.restart();
        return;
    }

    if (fullPath.startsWith("/api/password")) {
        if (method != "POST") {
            String resp = "{\"error\":\"method not allowed\"}";
            sendJson(client, 405, "Method Not Allowed", resp);
            return;
        }
        // parse {"oldPassword":"...","newPassword":"..."}
        String oldp, newp;
        int i1 = bodyIn.indexOf("\"oldPassword\"");
        if (i1 >= 0) {
            int co = bodyIn.indexOf(':', i1);
            int q1 = bodyIn.indexOf('"', co + 1);
            int q2 = bodyIn.indexOf('"', q1 + 1);
            if (co >= 0 && q1 >= 0 && q2 > q1) oldp = bodyIn.substring(q1 + 1, q2);
        }
        int i2 = bodyIn.indexOf("\"newPassword\"");
        if (i2 >= 0) {
            int co = bodyIn.indexOf(':', i2);
            int q1 = bodyIn.indexOf('"', co + 1);
            int q2 = bodyIn.indexOf('"', q1 + 1);
            if (co >= 0 && q1 >= 0 && q2 > q1) newp = bodyIn.substring(q1 + 1, q2);
        }
        if (oldp != g_password || newp.length() == 0) {
            String resp = "{\"error\":\"invalid password\"}";
            sendJson(client, 400, "Bad Request", resp);
            return;
        }
        if (!savePassword(newp)) {
            String resp = "{\"error\":\"save failed\"}";
            sendJson(client, 500, "Internal Server Error", resp);
            return;
        }
        String resp = "{\"updated\":true}";
        sendJson(client, 200, "OK", resp);
        return;
    }

    String resp = "{\"error\":\"not found\"}";
    sendJson(client, 404, "Not Found", resp);
}

static void handleApiOtaUpload(EthernetClient &client, const String &method, const HttpHeaders &headers, int contentLength)
{
    if (method != "POST") {
        String resp = "{\"error\":\"method not allowed\"}";
        sendJson(client, 405, "Method Not Allowed", resp);
        return;
    }
    if (!isAuthorized(headers)) {
        String resp = "{\"error\":\"unauthorized\"}";
        sendJson(client, 401, "Unauthorized", resp);
        return;
    }
    if (contentLength <= 0) {
        String resp = "{\"error\":\"missing content-length\"}";
        sendJson(client, 411, "Length Required", resp);
        return;
    }

    // Démarre la mise à jour avec la taille annoncée
    if (!Update.begin((size_t)contentLength)) {
        String resp = "{\"error\":\"update begin failed\"}";
        sendJson(client, 500, "Internal Server Error", resp);
        return;
    }

    const size_t bufSize = 1024;
    uint8_t *buffer = (uint8_t*)malloc(bufSize);
    if (!buffer) {
        Update.abort();
        String resp = "{\"error\":\"no memory\"}";
        sendJson(client, 500, "Internal Server Error", resp);
        return;
    }

    size_t received = 0;
    unsigned long lastProgress = millis();
    const unsigned long timeoutMs = 60000; // 60s de timeout global pour l'upload

    while (received < (size_t)contentLength && client.connected() && (millis() - lastProgress) < timeoutMs) {
        int avail = client.available();
        if (avail <= 0) {
            yield();
            continue;
        }
        size_t toRead = (size_t)avail;
        if (toRead > bufSize) toRead = bufSize;
        size_t remaining = (size_t)contentLength - received;
        if (toRead > remaining) toRead = remaining;
        int r = client.read(buffer, toRead);
        if (r <= 0) {
            yield();
            continue;
        }
        size_t w = Update.write(buffer, (size_t)r);
        if (w != (size_t)r) {
            free(buffer);
            Update.abort();
            String resp = "{\"error\":\"write failed\"}";
            sendJson(client, 500, "Internal Server Error", resp);
            return;
        }
        received += (size_t)r;
        lastProgress = millis();
    }

    free(buffer);

    if (received != (size_t)contentLength) {
        Update.abort();
        String resp = "{\"error\":\"incomplete upload\"}";
        sendJson(client, 400, "Bad Request", resp);
        return;
    }

    if (!Update.end(true)) {
        String resp = "{\"error\":\"update end failed\"}";
        sendJson(client, 500, "Internal Server Error", resp);
        return;
    }

    String ok = "{\"updated\":true,\"rebooting\":true}";
    sendJson(client, 200, "OK", ok);
    client.flush();
    {
        unsigned long waitStart = millis();
        while (millis() - waitStart < 300UL) {
            if (!client.connected()) break;
            yield();
        }
    }
    client.stop();
    ESP.restart();
}

// Définition après les objets MQTT pour éviter les erreurs de portée
static void openDore()
{
    Serial.println("openDore");
    unsigned long now = millis();
    // Rollover-safe: si now n'a pas encore atteint g_gacheCooldownUntilMs, la différence signée est négative
    if ((long)(now - g_gacheCooldownUntilMs) < 0) {
        return; // Anti-rafale sur la période DELAY_AWAIT_GACHE
    }
    // Impulsion active bas sur la gâche
    digitalWrite(PIN_OUT_GACHE, LOW);
    g_gacheActiveUntilMs = now + (unsigned long)DELAY_GACHE;
    g_gacheCooldownUntilMs = now + (unsigned long)DELAY_AWAIT_GACHE;

    // Notification immédiate sur MQTT de l'action d'ouverture
    if (g_mqtt.host.length() > 0 && mqttClient.connected()) {
        String topic = g_mqtt.baseTopic + "/action";
        String payload = String("{\"location\":\"door\",\"action\":\"open\"}");
        mqttClient.publish(topic.c_str(), payload.c_str());
    }
}

static void handleHttpClient(EthernetClient client)
{
    // Wait for data or timeout (~2s)
    unsigned long start = millis();
    while (client.connected() && !client.available() && millis() - start < 2000) {
        yield();
    }
    if (!client.available()) {
        client.stop();
        return;
    }

    // Read request line
    String method = client.readStringUntil(' ');
    String fullPath = client.readStringUntil(' ');
    Serial.print("HTTP req: "); Serial.print(method); Serial.print(" "); Serial.println(fullPath);
    // Discard the rest of the line
    client.readStringUntil('\n');

    // Consume headers until empty line
    HttpHeaders headers;
    int contentLength = 0;
    while (client.connected()) {
        String line = client.readStringUntil('\n');
        if (line.length() <= 2) break; // \r\n
        line.trim();
        int colon = line.indexOf(':');
        if (colon > 0 && headers.count < 16) {
            String name = line.substring(0, colon);
            String value = line.substring(colon + 1);
            value.trim();
            headers.items[headers.count].name = name;
            headers.items[headers.count].value = value;
            headers.count++;
            if (name.equalsIgnoreCase("Content-Length")) {
                contentLength = value.toInt();
            }
        }
    }

    String body = "";
    bool isOtaUpload = (method == "POST" && fullPath.startsWith("/api/ota"));
    if (!isOtaUpload && method == "POST" && contentLength > 0) {
        unsigned long startBody = millis();
        while ((int)body.length() < contentLength && client.connected() && millis() - startBody < 2000) {
            while (client.available() && (int)body.length() < contentLength) {
                char c = (char)client.read();
                body += c;
            }
            yield();
        }
    }

    if (method != "GET" && method != "HEAD" && method != "POST") {
        const char *txt = "Method Not Allowed";
        sendHttpHeader(client, 405, "Method Not Allowed", "text/plain; charset=utf-8", strlen(txt), false);
        if (method != "HEAD") client.print(txt);
        client.stop();
        return;
    }

    // Route API first
    if (fullPath.startsWith("/api/")) {
        if (isOtaUpload && fullPath.startsWith("/api/ota")) {
            handleApiOtaUpload(client, method, headers, contentLength);
            // handler gère lui-même l'arrêt et potentiellement le reboot
            return;
        }
        handleApiEx(client, fullPath, method, headers, body);
        client.stop();
        return;
    }

    String path = fullPath;
    if (path == "/") {
        path = mapToExistingIndex();
        if (path.length() == 0) {
            const char *body = "No index.html available";
            sendHttpHeader(client, 404, "Not Found", "text/plain; charset=utf-8", strlen(body), false);
            client.print(body);
            client.stop();
            return;
        }
    }

    const web_asset_t *asset = findAsset(path);
    if (!asset) {
        const char *body = "Not Found";
        sendHttpHeader(client, 404, "Not Found", "text/plain; charset=utf-8", strlen(body), false);
        client.print(body);
        client.stop();
        return;
    }

    sendHttpHeader(client, 200, "OK", asset->mime, asset->size, true);
    if (method != "HEAD") {
        writeAll(client, asset->data, asset->size);
    }
    client.stop();
}

void setup()
{
    Serial.begin(115200);

    // Detect first boot after flashing this firmware build and reset only password
    handleFirstBootOfBuild();

    // Load password from NVS (default to 1234 on first boot)
    loadPassword();
    Serial.println("Auth password loaded (hidden)");

    // Template: aucun réglage gate spécifique (autoClose/invertMotor) à charger

    // Reset W5500 (active low)
    pinMode(ETH_RST_PIN, OUTPUT);
    digitalWrite(ETH_RST_PIN, LOW);
    {
        unsigned long t0 = millis();
        while (millis() - t0 < 50UL) {
            yield();
        }
    }
    digitalWrite(ETH_RST_PIN, HIGH);
    {
        unsigned long t0 = millis();
        while (millis() - t0 < 100UL) {
            yield();
        }
    }

    // Init SPI and Ethernet driver
    SPI.begin(ETH_SCLK_PIN, ETH_MISO_PIN, ETH_MOSI_PIN);
    Ethernet.init(ETH_CS_PIN);

    // Le W5500 n'a pas d'adresse MAC propre, on la génère à partir de la MAC WiFi de l'ESP32
    // et on ajoute 1 au dernier octet pour le chip Ethernet afin d'être unique sur le réseau local
    static byte mac[6];
    {
        byte baseMac[6];
        esp_read_mac(baseMac, ESP_MAC_WIFI_STA);
        mac[0] = baseMac[0];
        mac[1] = baseMac[1];
        mac[2] = baseMac[2];
        mac[3] = baseMac[3];
        mac[4] = baseMac[4];
        mac[5] = static_cast<byte>(baseMac[5] + 1);
    }

    // Configuration réseau: applique la config NVS si existante, sinon fallback build, sinon DHCP
    applyNetworkWithFallback(mac);

    // Affiche l'adresse IP obtenue
    Serial.print("IPv4: ");
    Serial.println(Ethernet.localIP());

    // Broches
    pinMode(PIN_IN_BOUTON, INPUT_PULLUP);
    pinMode(PIN_IN_PORTE_RUE, INPUT_PULLUP);
    pinMode(PIN_IN_PORTE_TERRAIN, INPUT_PULLUP);
    pinMode(PIN_IN_FENTE, INPUT_PULLUP);
    pinMode(PIN_IN_CLE, INPUT_PULLUP);
    pinMode(PIN_OUT_GACHE, OUTPUT);
    pinMode(PIN_OUT_LUMIERE, OUTPUT);
    digitalWrite(PIN_OUT_GACHE, HIGH);   // repos: inactif (actif bas)
    digitalWrite(PIN_OUT_LUMIERE, LOW);  // lumière éteinte au démarrage

    // Init états précédents
    g_prevBouton = digitalRead(PIN_IN_BOUTON);
    g_prevCle = digitalRead(PIN_IN_CLE);
    g_prevRue = digitalRead(PIN_IN_PORTE_RUE);
    g_prevTerrain = digitalRead(PIN_IN_PORTE_TERRAIN);
    g_prevFente = digitalRead(PIN_IN_FENTE);

    httpServer.begin();

    // Charger configuration MQTT (depuis NVS si présente) et préparer le client
    loadMqttSettings();
    mqttClient.setCallback(callback);
    Serial.println("MQTT ready (waiting for configuration if host empty)");
}

void loop() {
    ensureMqttConnected();
    mqttClient.loop();

    // Suppression du heartbeat MQTT périodique (pas de spam sur /uptime)

    // Gestion temporisation gâche (rollover-safe)
    if (g_gacheActiveUntilMs != 0) {
        unsigned long now2 = millis();
        if ((long)(now2 - g_gacheActiveUntilMs) >= 0) {
            digitalWrite(PIN_OUT_GACHE, HIGH); // fin d'impulsion
            g_gacheActiveUntilMs = 0;
        } else {
            digitalWrite(PIN_OUT_GACHE, LOW);
        }
    }

    // Lecture entrées et détection d'edges
    int vBouton = digitalRead(PIN_IN_BOUTON);
    int vCle = digitalRead(PIN_IN_CLE);
    int vRue = digitalRead(PIN_IN_PORTE_RUE);
    int vTerrain = digitalRead(PIN_IN_PORTE_TERRAIN);
    int vFente = digitalRead(PIN_IN_FENTE);

    // Déclenchement porte si bouton ou clé passent à BAS (actif bas)
    if (g_prevBouton != -1 && vBouton != g_prevBouton && vBouton == LOW) {
        openDore();
    }
    if (g_prevCle != -1 && vCle != g_prevCle && vCle == LOW) {
        openDore();
    }

    // Publications MQTT sur changements d'états
    auto publishIfChanged = [&](const char* location, int prev, int nowv){
        if (g_mqtt.host.length() == 0 || !mqttClient.connected()) return;
        if (prev == -1 || nowv == prev) return;
        String topic = g_mqtt.baseTopic + "/action";
        String payload = String("{\"location\":\"") + location + "\",\"action\":\"" + (nowv == HIGH ? "open" : "close") + "\"}";
        mqttClient.publish(topic.c_str(), payload.c_str());
    };
    publishIfChanged("street", g_prevRue, vRue);
    publishIfChanged("house", g_prevTerrain, vTerrain);
    publishIfChanged("slot", g_prevFente, vFente);

    // MàJ états précédents
    g_prevBouton = vBouton;
    g_prevCle = vCle;
    g_prevRue = vRue;
    g_prevTerrain = vTerrain;
    g_prevFente = vFente;

    // Logique lumière: on si une des portes est ouverte OU forçage manuel
    bool autoLight = (vRue == HIGH) || (vTerrain == HIGH);
    bool wantLight = g_forceLight || autoLight;
    digitalWrite(PIN_OUT_LUMIERE, wantLight ? HIGH : LOW);

    // Handle HTTP client connections
    EthernetClient httpClient = httpServer.available();
    if (httpClient) {
        handleHttpClient(httpClient);
    }

    // Reboot différé si demandé (laisse le temps à la réponse HTTP d'être envoyée)
    if (g_rebootRequested) {
        unsigned long now3 = millis();
        if ((long)(now3 - g_rebootAtMs) >= 0) {
            g_rebootRequested = false;
            Serial.println("Rebooting to apply MQTT settings...");
            ESP.restart();
        }
    }
}
