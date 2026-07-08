#include "pup_trophy.h"
#include "pup_trophy_icons.h"

#include <string.h>
#include <ctype.h>
#include "nvs.h"
#include "esp_log.h"

static const char *TAG = "sc_trophy";

#define PT_NS        "uicfg"
#define PT_K_COUNTS  "vp_tc"
#define PT_K_EARNED  "vp_tre"
#define PT_K_BOOTS   "vp_trb"
#define PT_K_BLOOM   "vp_scb"

enum {
    TC_WIFI = 0,
    TC_BLE,
    TC_SCANS,
    TC_SCENTS,
    TC_HIDDEN,
    TC_5G,
    TC_OPEN,
    TC_WPA3,
    TC_ENTERPRISE,
    TC_CONSUMER,
    TC_IOT,
    TC_SURVEIL,
    TC_AXON,
    TC_FLOCK,
    TC_INVEST,
    TC_TRACKER,
    TC_AIRTAG,
    TC_DRONE,
    TC_PWNAGOTCHI,
    TC_DEAUTH,
    TC_TWIN,
    TC_PMKID,
    TC_MALICIOUS,
    TC_SAFE_SCANS,
    TC_THREAT_SCANS,
    TC_PHONE,
    TC_LAPTOP,
    TC_WEARABLE,
    TC_AUDIO,
    TC_MEDICAL,
    TC_VEHICLE,
    TC_MAKER,
    TC_DEVMOD,
    TC_BEACON,
    TC_POS,
    TC_ACCESS,
    TC_INFRA,
    TC_CLOSE,
    TC_STRONG,
    TC_EMPTY_SCANS,
    TC_BIG_SCANS,
    TC_BUSY_SCANS,
    TC_COUNT
};

#define SRC_LEVEL  0xFE
#define SRC_AGE    0xFD

static const uint32_t WEIGHT_XP[6] = { 0, 10, 30, 90, 270, 810 };
#define SCENT_XP 5

typedef struct {
    const char *name;
    uint8_t     src;
    uint32_t    threshold;
    uint8_t     weight;
    uint8_t     icon;
} trophy_def_t;

static const trophy_def_t TROPHIES[] = {

    { "First Bite",         TC_WIFI,        1,       1, PUP_ICON_BONE },
    { "Snack Time",         TC_WIFI,        50,      1, PUP_ICON_BONE },
    { "Full Bowl",          TC_WIFI,        250,     2, PUP_ICON_BONE },
    { "Kibble Counter",     TC_WIFI,        1000,    2, PUP_ICON_BONE },
    { "Buffet Hound",       TC_WIFI,        5000,    3, PUP_ICON_BONE },
    { "Chow Champion",      TC_WIFI,        25000,   4, PUP_ICON_BONE },
    { "Bottomless Bowl",    TC_WIFI,        100000,  4, PUP_ICON_BONE },
    { "Apex Appetite",      TC_WIFI,        1000000, 5, PUP_ICON_BONE },

    { "First Crumb",        TC_BLE,         1,       1, PUP_ICON_BOWL },
    { "Treat Snatcher",     TC_BLE,         50,      1, PUP_ICON_BOWL },
    { "Crumb Tracker",      TC_BLE,         250,     2, PUP_ICON_BOWL },
    { "Biscuit Baron",      TC_BLE,         1000,    2, PUP_ICON_BOWL },
    { "Morsel Mountain",    TC_BLE,         5000,    3, PUP_ICON_BOWL },
    { "Snuffle Storm",      TC_BLE,         25000,   4, PUP_ICON_BOWL },
    { "Crumb Tsunami",      TC_BLE,         100000,  4, PUP_ICON_BOWL },
    { "Cosmic Crumbs",      TC_BLE,         1000000, 5, PUP_ICON_BOWL },

    { "First Walk",         TC_SCANS,       1,       1, PUP_ICON_PAW },
    { "Around the Block",   TC_SCANS,       5,       1, PUP_ICON_PAW },
    { "Daily Stroller",     TC_SCANS,       25,      2, PUP_ICON_PAW },
    { "Neighborhood Watch", TC_SCANS,       100,     2, PUP_ICON_PAW },
    { "Trail Hound",        TC_SCANS,       250,     3, PUP_ICON_PAW },
    { "Marathon Mutt",      TC_SCANS,       500,     3, PUP_ICON_PAW },
    { "Thousand Mile Paws", TC_SCANS,       1000,    4, PUP_ICON_PAW },
    { "Globe Trotter",      TC_SCANS,       5000,    5, PUP_ICON_PAW },

    { "New Scent",          TC_SCENTS,      1,       1, PUP_ICON_NOSE },
    { "Curious Nose",       TC_SCENTS,      10,      1, PUP_ICON_NOSE },
    { "Scent Hound",        TC_SCENTS,      50,      2, PUP_ICON_NOSE },
    { "Bloodhound",         TC_SCENTS,      150,     3, PUP_ICON_NOSE },
    { "Master Sniffer",     TC_SCENTS,      400,     3, PUP_ICON_NOSE },
    { "Encyclopedic Nose",  TC_SCENTS,      1000,    4, PUP_ICON_NOSE },
    { "The Nose Knows All", TC_SCENTS,      2500,    5, PUP_ICON_NOSE },

    { "Growing Pup",        SRC_LEVEL,      2,       1, PUP_ICON_TROPHY },
    { "Big Pup Now",        SRC_LEVEL,      5,       1, PUP_ICON_TROPHY },
    { "Double Digits",      SRC_LEVEL,      10,      2, PUP_ICON_TROPHY },
    { "Young Gun",          SRC_LEVEL,      15,      2, PUP_ICON_TROPHY },
    { "Top Dog",            SRC_LEVEL,      20,      3, PUP_ICON_TROPHY },
    { "Pack Leader",        SRC_LEVEL,      30,      4, PUP_ICON_TROPHY },
    { "Old Guard",          SRC_LEVEL,      40,      4, PUP_ICON_TROPHY },
    { "Living Legend",      SRC_LEVEL,      50,      5, PUP_ICON_TROPHY },

    { "Ten Boots Old",      SRC_AGE,        10,      1, PUP_ICON_CAKE },
    { "Thirty Boots",       SRC_AGE,        30,      2, PUP_ICON_CAKE },
    { "Boot Centennial",    SRC_AGE,        100,     2, PUP_ICON_CAKE },
    { "A Year of Boots",    SRC_AGE,        365,     3, PUP_ICON_CAKE },
    { "Thousand Boots",     SRC_AGE,        1000,    4, PUP_ICON_CAKE },
    { "Ancient Companion",  SRC_AGE,        2500,    5, PUP_ICON_CAKE },

    { "Hide and Seek",      TC_HIDDEN,      1,       1, PUP_ICON_GHOST },
    { "Ghost Hunter",       TC_HIDDEN,      10,      2, PUP_ICON_GHOST },
    { "Seance Regular",     TC_HIDDEN,      50,      2, PUP_ICON_GHOST },
    { "Phantom Finder",     TC_HIDDEN,      250,     3, PUP_ICON_GHOST },
    { "Spirit Medium",      TC_HIDDEN,      1000,    4, PUP_ICON_GHOST },
    { "Ghost Town Mayor",   TC_HIDDEN,      5000,    5, PUP_ICON_GHOST },

    { "High Band Hound",    TC_5G,          1,       1, PUP_ICON_WAVE },
    { "Five Gig Fan",       TC_5G,          25,      1, PUP_ICON_WAVE },
    { "Spectrum Surfer",    TC_5G,          100,     2, PUP_ICON_WAVE },
    { "Wideband Wanderer",  TC_5G,          500,     3, PUP_ICON_WAVE },
    { "Gigahertz Gourmet",  TC_5G,          2500,    4, PUP_ICON_WAVE },
    { "Band Commander",     TC_5G,          10000,   5, PUP_ICON_WAVE },

    { "Open Door",          TC_OPEN,        1,       1, PUP_ICON_LOCK },
    { "Unlocked Alley",     TC_OPEN,        25,      2, PUP_ICON_LOCK },
    { "Free For All",       TC_OPEN,        100,     2, PUP_ICON_LOCK },
    { "No Locks Land",      TC_OPEN,        500,     3, PUP_ICON_LOCK },
    { "Wild West WiFi",     TC_OPEN,        2500,    4, PUP_ICON_LOCK },

    { "Modern Times",       TC_WPA3,        1,       1, PUP_ICON_SHIELD },
    { "Shield Spotter",     TC_WPA3,        10,      2, PUP_ICON_SHIELD },
    { "Armored Convoy",     TC_WPA3,        50,      3, PUP_ICON_SHIELD },
    { "Fort Knox Files",    TC_WPA3,        250,     3, PUP_ICON_SHIELD },
    { "Crypto Connoisseur", TC_WPA3,        1000,    4, PUP_ICON_SHIELD },

    { "Office Visit",       TC_ENTERPRISE,  1,       1, PUP_ICON_CASE },
    { "Cubicle Cruiser",    TC_ENTERPRISE,  25,      2, PUP_ICON_CASE },
    { "Dedicated Worker",   TC_ENTERPRISE,  100,     2, PUP_ICON_CASE },
    { "Corporate Climber",  TC_ENTERPRISE,  500,     3, PUP_ICON_CASE },
    { "Boardroom Regular",  TC_ENTERPRISE,  2500,    4, PUP_ICON_CASE },
    { "CEO of Sniffing",    TC_ENTERPRISE,  10000,   5, PUP_ICON_CASE },

    { "Home Sweet Home",    TC_CONSUMER,    1,       1, PUP_ICON_COUCH },
    { "Couch Potato",       TC_CONSUMER,    25,      2, PUP_ICON_COUCH },
    { "Suburb Sniffer",     TC_CONSUMER,    100,     2, PUP_ICON_COUCH },
    { "Cul-de-sac King",    TC_CONSUMER,    500,     3, PUP_ICON_COUCH },
    { "HOA Honorary",       TC_CONSUMER,    2500,    4, PUP_ICON_COUCH },
    { "Mayor of Suburbia",  TC_CONSUMER,    10000,   5, PUP_ICON_COUCH },

    { "Smart Home Sniff",   TC_IOT,         1,       1, PUP_ICON_BULB },
    { "Gadget Garden",      TC_IOT,         25,      2, PUP_ICON_BULB },
    { "Talking Toasters",   TC_IOT,         100,     3, PUP_ICON_BULB },
    { "Internet of Dogs",   TC_IOT,         500,     3, PUP_ICON_BULB },
    { "Swarm Keeper",       TC_IOT,         2500,    4, PUP_ICON_BULB },

    { "Camera Shy",         TC_SURVEIL,     1,       2, PUP_ICON_CAM },
    { "Watching Watchers",  TC_SURVEIL,     5,       2, PUP_ICON_CAM },
    { "Counter Surveyor",   TC_SURVEIL,     25,      3, PUP_ICON_CAM },
    { "Panopticon Walker",  TC_SURVEIL,     100,     3, PUP_ICON_CAM },
    { "Surveillance State", TC_SURVEIL,     500,     4, PUP_ICON_CAM },
    { "Big Brother Census", TC_SURVEIL,     1000,    5, PUP_ICON_CAM },

    { "Badge Sniffer",      TC_AXON,        1,       3, PUP_ICON_BADGE },
    { "Beat Patrol",        TC_AXON,        3,       3, PUP_ICON_BADGE },
    { "Precinct Tour",      TC_AXON,        10,      4, PUP_ICON_BADGE },
    { "Squad Car Census",   TC_AXON,        25,      4, PUP_ICON_BADGE },
    { "Internal Affairs",   TC_AXON,        100,     5, PUP_ICON_BADGE },
    { "Police Procedural",  TC_AXON,        250,     5, PUP_ICON_BADGE },

    { "Bird Watcher",       TC_FLOCK,       1,       3, PUP_ICON_BIRD },
    { "Early Bird",         TC_FLOCK,       3,       3, PUP_ICON_BIRD },
    { "Birds on Wires",     TC_FLOCK,       10,      4, PUP_ICON_BIRD },
    { "Flock Together",     TC_FLOCK,       25,      4, PUP_ICON_BIRD },
    { "Murmuration",        TC_FLOCK,       100,     5, PUP_ICON_BIRD },
    { "Full Aviary",        TC_FLOCK,       250,     5, PUP_ICON_BIRD },

    { "Script Puppy",       TC_INVEST,      1,       2, PUP_ICON_SPY },
    { "Tool Spotter",       TC_INVEST,      3,       3, PUP_ICON_SPY },
    { "Pentester",          TC_INVEST,      10,      4, PUP_ICON_SPY },
    { "Red Team Regular",   TC_INVEST,      25,      4, PUP_ICON_SPY },
    { "Con Circuit",        TC_INVEST,      100,     5, PUP_ICON_SPY },
    { "APT Whisperer",      TC_INVEST,      250,     5, PUP_ICON_SPY },

    { "Met Another Dog",    TC_PWNAGOTCHI,  1,       4, PUP_ICON_DOG },
    { "Pack Mates",         TC_PWNAGOTCHI,  5,       4, PUP_ICON_DOG },
    { "Dog Park",           TC_PWNAGOTCHI,  25,      5, PUP_ICON_DOG },
    { "Alpha of Alphas",    TC_PWNAGOTCHI,  100,     5, PUP_ICON_DOG },

    { "Tag Along",          TC_TRACKER,     1,       1, PUP_ICON_TAG },
    { "Tag Collector",      TC_TRACKER,     5,       2, PUP_ICON_TAG },
    { "Lost and Found",     TC_TRACKER,     25,      3, PUP_ICON_TAG },
    { "Bag Tag Bingo",      TC_TRACKER,     100,     3, PUP_ICON_TAG },
    { "Tracker Tracker",    TC_TRACKER,     500,     4, PUP_ICON_TAG },
    { "Tagged Universe",    TC_TRACKER,     1000,    5, PUP_ICON_TAG },

    { "Apple Picker",       TC_AIRTAG,      1,       2, PUP_ICON_TAG },
    { "Orchard Stroll",     TC_AIRTAG,      5,       2, PUP_ICON_TAG },
    { "Apple Harvest",      TC_AIRTAG,      25,      3, PUP_ICON_TAG },
    { "Cider Press",        TC_AIRTAG,      100,     4, PUP_ICON_TAG },

    { "Eyes Up",            TC_DRONE,       1,       2, PUP_ICON_DRONE },
    { "Crowded Sky",        TC_DRONE,       3,       3, PUP_ICON_DRONE },
    { "Air Traffic Ctrl",   TC_DRONE,       10,      3, PUP_ICON_DRONE },
    { "Drone Zone",         TC_DRONE,       50,      4, PUP_ICON_DRONE },
    { "Swarm Season",       TC_DRONE,       250,     4, PUP_ICON_DRONE },
    { "Sky Census",         TC_DRONE,       1000,    5, PUP_ICON_DRONE },

    { "Jam Session",        TC_DEAUTH,      1,       2, PUP_ICON_ZAP },
    { "Static Storm",       TC_DEAUTH,      5,       3, PUP_ICON_ZAP },
    { "Flood Warden",       TC_DEAUTH,      25,      3, PUP_ICON_ZAP },
    { "Storm Chaser",       TC_DEAUTH,      100,     4, PUP_ICON_ZAP },
    { "Hurricane Hunter",   TC_DEAUTH,      500,     5, PUP_ICON_ZAP },

    { "Seeing Double",      TC_TWIN,        1,       2, PUP_ICON_TWIN },
    { "Twin Spotter",       TC_TWIN,        5,       3, PUP_ICON_TWIN },
    { "Doppelganger Den",   TC_TWIN,        25,      3, PUP_ICON_TWIN },
    { "Hall of Mirrors",    TC_TWIN,        100,     4, PUP_ICON_TWIN },
    { "Masquerade Ball",    TC_TWIN,        500,     5, PUP_ICON_TWIN },

    { "Loose Key",          TC_PMKID,       1,       2, PUP_ICON_KEY },
    { "Key Ring",           TC_PMKID,       10,      3, PUP_ICON_KEY },
    { "Locksmith",          TC_PMKID,       50,      4, PUP_ICON_KEY },
    { "Skeleton Key",       TC_PMKID,       250,     5, PUP_ICON_KEY },

    { "Bad Actor",          TC_MALICIOUS,   1,       3, PUP_ICON_SKULL },
    { "Rogues Gallery",     TC_MALICIOUS,   5,       3, PUP_ICON_SKULL },
    { "Most Wanted Wall",   TC_MALICIOUS,   25,      4, PUP_ICON_SKULL },
    { "Villain Census",     TC_MALICIOUS,   100,     5, PUP_ICON_SKULL },

    { "All Clear",          TC_SAFE_SCANS,  1,       1, PUP_ICON_SUN },
    { "Quiet Streets",      TC_SAFE_SCANS,  10,      2, PUP_ICON_SUN },
    { "Safe Routes",        TC_SAFE_SCANS,  50,      3, PUP_ICON_SUN },
    { "Guardian Angel",     TC_SAFE_SCANS,  250,     4, PUP_ICON_SUN },
    { "Peacekeeper",        TC_SAFE_SCANS,  1000,    5, PUP_ICON_SUN },

    { "Hot Zone",           TC_THREAT_SCANS, 1,      2, PUP_ICON_WARN },
    { "Danger Tourist",     TC_THREAT_SCANS, 10,     2, PUP_ICON_WARN },
    { "Storm Walker",       TC_THREAT_SCANS, 50,     3, PUP_ICON_WARN },
    { "War Zone Reporter",  TC_THREAT_SCANS, 250,    4, PUP_ICON_WARN },
    { "Unshakeable",        TC_THREAT_SCANS, 1000,   5, PUP_ICON_WARN },

    { "Phone Spotter",      TC_PHONE,       1,       1, PUP_ICON_PHONE },
    { "Pocket Census",      TC_PHONE,       50,      2, PUP_ICON_PHONE },
    { "Crowd Counter",      TC_PHONE,       500,     3, PUP_ICON_PHONE },
    { "Stadium Sweep",      TC_PHONE,       5000,    4, PUP_ICON_PHONE },

    { "Laptop Lounge",      TC_LAPTOP,      1,       1, PUP_ICON_LAPTOP },
    { "Coffee Shop Vibes",  TC_LAPTOP,      25,      2, PUP_ICON_LAPTOP },
    { "Open Office Plan",   TC_LAPTOP,      250,     3, PUP_ICON_LAPTOP },

    { "Wrist Watcher",      TC_WEARABLE,    1,       1, PUP_ICON_WATCH },
    { "Step Counter",       TC_WEARABLE,    25,      2, PUP_ICON_WATCH },
    { "Marathon Crowd",     TC_WEARABLE,    250,     3, PUP_ICON_WATCH },

    { "Earbud Echo",        TC_AUDIO,       1,       1, PUP_ICON_NOTE },
    { "Silent Disco",       TC_AUDIO,       25,      2, PUP_ICON_NOTE },
    { "Orchestra Pit",      TC_AUDIO,       250,     3, PUP_ICON_NOTE },

    { "Checkup Time",       TC_MEDICAL,     1,       2, PUP_ICON_CROSS },
    { "Ward Rounds",        TC_MEDICAL,     5,       3, PUP_ICON_CROSS },
    { "Night Shift",        TC_MEDICAL,     25,      4, PUP_ICON_CROSS },
    { "Field Hospital",     TC_MEDICAL,     100,     5, PUP_ICON_CROSS },

    { "Parking Lot Pup",    TC_VEHICLE,     1,       1, PUP_ICON_CAR },
    { "Traffic Counter",    TC_VEHICLE,     25,      2, PUP_ICON_CAR },
    { "Rush Hour",          TC_VEHICLE,     250,     3, PUP_ICON_CAR },

    { "Garage Tinkerer",    TC_MAKER,       1,       1, PUP_ICON_WRENCH },
    { "Hackerspace Tour",   TC_MAKER,       25,      2, PUP_ICON_WRENCH },
    { "Maker Faire",        TC_MAKER,       250,     3, PUP_ICON_WRENCH },

    { "Bare Metal",         TC_DEVMOD,      1,       1, PUP_ICON_CHIP },
    { "Breadboard Buffet",  TC_DEVMOD,      25,      2, PUP_ICON_CHIP },
    { "Silicon Valley",     TC_DEVMOD,      250,     3, PUP_ICON_CHIP },

    { "Lighthouse Keeper",  TC_BEACON,      1,       1, PUP_ICON_DOT },
    { "Constellation",      TC_BEACON,      100,     3, PUP_ICON_DOT },

    { "Window Shopper",     TC_POS,         1,       2, PUP_ICON_CASH },
    { "Mall Crawl",         TC_POS,         50,      3, PUP_ICON_CASH },

    { "Doorman",            TC_ACCESS,      1,       2, PUP_ICON_DOOR },
    { "Master of Keys",     TC_ACCESS,      50,      3, PUP_ICON_DOOR },

    { "Backbone Sniff",     TC_INFRA,       1,       2, PUP_ICON_TOWER },
    { "Grid Walker",        TC_INFRA,       100,     3, PUP_ICON_TOWER },

    { "Personal Space",     TC_CLOSE,       1,       1, PUP_ICON_NOSE },
    { "Nose to Nose",       TC_CLOSE,       100,     3, PUP_ICON_NOSE },
    { "Right On Top",       TC_STRONG,      1,       1, PUP_ICON_WAVE },
    { "Antenna Hugger",     TC_STRONG,      50,      3, PUP_ICON_WAVE },
    { "Desert Walk",        TC_EMPTY_SCANS, 1,       1, PUP_ICON_PAW },
    { "Lone Wolf",          TC_EMPTY_SCANS, 25,      3, PUP_ICON_PAW },
    { "Feast Day",          TC_BIG_SCANS,   1,       2, PUP_ICON_BONE },
    { "Banquet Circuit",    TC_BIG_SCANS,   25,      4, PUP_ICON_BONE },
    { "Packed House",       TC_BUSY_SCANS,  1,       2, PUP_ICON_BOWL },
    { "Festival Season",    TC_BUSY_SCANS,  25,      4, PUP_ICON_BOWL },
};

_Static_assert(sizeof(TROPHIES) / sizeof(TROPHIES[0]) == PUP_TROPHY_COUNT,
               "trophy table must hold exactly PUP_TROPHY_COUNT entries");

#define EARNED_BYTES  32
#define BLOOM_BYTES   256 

static uint32_t s_counts[TC_COUNT]          = {0};
static uint8_t  s_earned[EARNED_BYTES]      = {0};
static uint16_t s_boots[PUP_TROPHY_COUNT]   = {0};
static uint8_t  s_bloom[BLOOM_BYTES]        = {0};
static uint16_t s_pending_scents            = 0;
static bool     s_bloom_dirty               = false;

static inline bool earned(uint16_t id)
{
    return (s_earned[id >> 3] >> (id & 7)) & 1;
}

static inline void set_earned(uint16_t id)
{
    s_earned[id >> 3] |= (uint8_t)(1u << (id & 7));
}

static void load_blob(nvs_handle_t h, const char *key, void *dst, size_t cap)
{
    size_t len = cap;
    if (nvs_get_blob(h, key, dst, &len) != ESP_OK) {
        memset(dst, 0, cap);
    }
}

void pup_trophy_init(void)
{
    nvs_handle_t h;
    if (nvs_open(PT_NS, NVS_READONLY, &h) == ESP_OK) {
        load_blob(h, PT_K_COUNTS, s_counts, sizeof(s_counts));
        load_blob(h, PT_K_EARNED, s_earned, sizeof(s_earned));
        load_blob(h, PT_K_BOOTS,  s_boots,  sizeof(s_boots));
        load_blob(h, PT_K_BLOOM,  s_bloom,  sizeof(s_bloom));
        nvs_close(h);
    }
    ESP_LOGI(TAG, "trophies loaded: %u/%u earned, %u scents, %u scans",
             (unsigned)pup_trophy_earned_count(), PUP_TROPHY_COUNT,
             (unsigned)s_counts[TC_SCENTS], (unsigned)s_counts[TC_SCANS]);
}

static void pup_trophy_save(bool earned_dirty)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(PT_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "save open failed: %s", esp_err_to_name(err));
        return;
    }
    nvs_set_blob(h, PT_K_COUNTS, s_counts, sizeof(s_counts));
    if (earned_dirty) {
        nvs_set_blob(h, PT_K_EARNED, s_earned, sizeof(s_earned));
        nvs_set_blob(h, PT_K_BOOTS, s_boots, sizeof(s_boots));
    }
    if (s_bloom_dirty) {
        nvs_set_blob(h, PT_K_BLOOM, s_bloom, sizeof(s_bloom));
        s_bloom_dirty = false;
    }
    nvs_commit(h);
    nvs_close(h);
}

static uint32_t fnv1a(const char *s, uint32_t seed)
{
    uint32_t hash = 2166136261u ^ seed;
    for (; *s; s++) {
        hash ^= (uint8_t)tolower((unsigned char)*s);
        hash *= 16777619u;
    }
    return hash;
}

bool pup_trophy_smell(const char *vendor)
{
    if (!vendor || !vendor[0]) return false;
    if (strcasecmp(vendor, "unknown") == 0 || strcmp(vendor, "?") == 0) {
        return false;
    }

    static const uint32_t seeds[3] = { 0, 0x9E3779B9u, 0x85EBCA6Bu };
    uint16_t bit[3];
    bool known = true;
    for (int i = 0; i < 3; i++) {
        bit[i] = (uint16_t)(fnv1a(vendor, seeds[i]) & (BLOOM_BYTES * 8 - 1));
        if (!((s_bloom[bit[i] >> 3] >> (bit[i] & 7)) & 1)) known = false;
    }
    if (known) return false;

    for (int i = 0; i < 3; i++) {
        s_bloom[bit[i] >> 3] |= (uint8_t)(1u << (bit[i] & 7));
    }
    s_bloom_dirty = true;
    s_pending_scents++;
    return true;
}

pup_trophy_feed_result_t pup_trophy_feed(const pup_scan_stats_t *st,
                                         uint32_t boot_count,
                                         uint16_t level,
                                         uint32_t age_boots)
{
    pup_trophy_feed_result_t r = {0};

    s_counts[TC_WIFI]       += st->wifi_n;
    s_counts[TC_BLE]        += st->ble_n;
    s_counts[TC_SCANS]      += 1;
    s_counts[TC_SCENTS]     += s_pending_scents;
    s_counts[TC_HIDDEN]     += st->hidden;
    s_counts[TC_5G]         += st->band5g;
    s_counts[TC_OPEN]       += st->open_nets;
    s_counts[TC_WPA3]       += st->wpa3;
    s_counts[TC_ENTERPRISE] += st->enterprise;
    s_counts[TC_CONSUMER]   += st->consumer;
    s_counts[TC_IOT]        += st->iot;
    s_counts[TC_SURVEIL]    += st->surveil;
    s_counts[TC_AXON]       += st->axon;
    s_counts[TC_FLOCK]      += st->flock;
    s_counts[TC_INVEST]     += st->investigation;
    s_counts[TC_TRACKER]    += st->tracker;
    s_counts[TC_AIRTAG]     += st->airtag;
    s_counts[TC_DRONE]      += st->drone;
    s_counts[TC_PWNAGOTCHI] += st->pwnagotchi;
    s_counts[TC_DEAUTH]     += st->deauth;
    s_counts[TC_TWIN]       += st->twin;
    s_counts[TC_PMKID]      += st->pmkid;
    s_counts[TC_MALICIOUS]  += st->malicious;
    s_counts[TC_PHONE]      += st->phone;
    s_counts[TC_LAPTOP]     += st->laptop;
    s_counts[TC_WEARABLE]   += st->wearable;
    s_counts[TC_AUDIO]      += st->audio;
    s_counts[TC_MEDICAL]    += st->medical;
    s_counts[TC_VEHICLE]    += st->vehicle;
    s_counts[TC_MAKER]      += st->maker;
    s_counts[TC_DEVMOD]     += st->devmod;
    s_counts[TC_BEACON]     += st->beacon;
    s_counts[TC_POS]        += st->pos;
    s_counts[TC_ACCESS]     += st->access;
    s_counts[TC_INFRA]      += st->infra;
    s_counts[TC_CLOSE]      += st->close_ble;
    s_counts[TC_STRONG]     += st->strong_wifi;
    if (st->env_threat == 0)              s_counts[TC_SAFE_SCANS]++;
    if (st->env_threat >= 3)              s_counts[TC_THREAT_SCANS]++;
    if (st->wifi_n == 0)                  s_counts[TC_EMPTY_SCANS]++;
    if (st->wifi_n >= 40)                 s_counts[TC_BIG_SCANS]++;
    if (st->ble_n >= 80)                  s_counts[TC_BUSY_SCANS]++;

    r.new_scents = s_pending_scents;
    r.bonus_xp   = (uint32_t)s_pending_scents * SCENT_XP;
    s_pending_scents = 0;

    uint16_t boot16 = (boot_count > UINT16_MAX) ? UINT16_MAX
                    : (boot_count == 0)         ? 1 : (uint16_t)boot_count;
    bool earned_dirty = false;

    for (uint16_t id = 0; id < PUP_TROPHY_COUNT; id++) {
        if (earned(id)) continue;
        const trophy_def_t *t = &TROPHIES[id];

        uint32_t cur;
        switch (t->src) {
        case SRC_LEVEL: cur = level;             break;
        case SRC_AGE:   cur = age_boots;         break;
        default:        cur = s_counts[t->src];  break;
        }
        if (cur < t->threshold) continue;

        set_earned(id);
        s_boots[id]  = boot16;
        earned_dirty = true;
        r.bonus_xp  += WEIGHT_XP[t->weight];
        if (r.new_count < PUP_TROPHY_MAX_NEW) {
            r.new_ids[r.new_count] = id;
        }
        r.new_count++;
        ESP_LOGI(TAG, "trophy earned: \"%s\" (w%u, +%u xp)",
                 t->name, (unsigned)t->weight,
                 (unsigned)WEIGHT_XP[t->weight]);
    }

    pup_trophy_save(earned_dirty);

    if (r.new_count || r.new_scents) {
        ESP_LOGI(TAG, "feed: +%u trophies, +%u scents, +%u bonus xp",
                 (unsigned)r.new_count, (unsigned)r.new_scents,
                 (unsigned)r.bonus_xp);
    }
    return r;
}

uint16_t pup_trophy_earned_count(void)
{
    uint16_t n = 0;
    for (uint16_t id = 0; id < PUP_TROPHY_COUNT; id++) {
        if (earned(id)) n++;
    }
    return n;
}

uint16_t pup_trophy_earned_at(uint16_t n)
{

    for (int8_t w = 5; w >= 1; w--) {
        for (uint16_t id = 0; id < PUP_TROPHY_COUNT; id++) {
            if (!earned(id) || TROPHIES[id].weight != (uint8_t)w) continue;
            if (n == 0) return id;
            n--;
        }
    }
    return 0xFFFF;
}

const char *pup_trophy_name(uint16_t id)
{
    return (id < PUP_TROPHY_COUNT) ? TROPHIES[id].name : "?";
}

uint8_t pup_trophy_weight(uint16_t id)
{
    return (id < PUP_TROPHY_COUNT) ? TROPHIES[id].weight : 1;
}

uint32_t pup_trophy_xp(uint16_t id)
{
    return (id < PUP_TROPHY_COUNT) ? WEIGHT_XP[TROPHIES[id].weight] : 0;
}

uint8_t pup_trophy_icon(uint16_t id)
{
    return (id < PUP_TROPHY_COUNT) ? TROPHIES[id].icon : PUP_ICON_BONE;
}

uint32_t pup_trophy_boot_earned(uint16_t id)
{
    if (id >= PUP_TROPHY_COUNT || !earned(id)) return 0;
    return s_boots[id];
}

uint32_t pup_trophy_scent_count(void)
{
    return s_counts[TC_SCENTS];
}

void pup_trophy_dump(void)
{
    static const char *const cnames[TC_COUNT] = {
        "wifi", "ble", "scans", "scents", "hidden", "5g", "open", "wpa3",
        "enterprise", "consumer", "iot", "surveil", "axon", "flock",
        "invest", "tracker", "airtag", "drone", "pwnagotchi", "deauth",
        "twin", "pmkid", "malicious", "safe_scans", "threat_scans", "phone",
        "laptop", "wearable", "audio", "medical", "vehicle", "maker",
        "devmod", "beacon", "pos", "access", "infra", "close", "strong",
        "empty_scans", "big_scans", "busy_scans",
    };
    ESP_LOGI(TAG, "TROPHIES %u/%u earned, %u scents",
             (unsigned)pup_trophy_earned_count(), PUP_TROPHY_COUNT,
             (unsigned)s_counts[TC_SCENTS]);
    for (int c = 0; c < TC_COUNT; c++) {
        if (s_counts[c]) {
            ESP_LOGI(TAG, "  count %-12s %u", cnames[c], (unsigned)s_counts[c]);
        }
    }
    for (uint16_t id = 0; id < PUP_TROPHY_COUNT; id++) {
        if (earned(id)) {
            ESP_LOGI(TAG, "  [%3u] \"%s\" w%u boot %u", (unsigned)id,
                     TROPHIES[id].name, (unsigned)TROPHIES[id].weight,
                     (unsigned)s_boots[id]);
        }
    }
}
