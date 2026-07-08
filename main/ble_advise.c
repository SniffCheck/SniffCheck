#include "ble_advise.h"
#include "eui_db.h"
#include "analyzer.h"
#include <stdio.h>
#include <string.h>

uint8_t ble_lite_reasons(const ble_device_t *d, char lines[2][64])
{
    if (!d || !lines) return 0;
    lines[0][0] = '\0';
    lines[1][0] = '\0';
    uint8_t n = 0;

    #define WRITE(fmt, ...) do { \
        if (n < 2) { snprintf(lines[n], 64, fmt, ##__VA_ARGS__); n++; } \
    } while (0)

    uint8_t cls = ble_effective_class(d);
    uint8_t cls_certain = ble_effective_class_certain(d);

    uint16_t combined = d->eui_flags | d->bt_company_flags | d->mfg_rule_flags
                      | d->uuid128_flags | d->name_rule_flags;

    if (combined & EUI_FLAG_KNOWN_MALICIOUS) {
        WRITE("Made from known hacking hardware.");
        WRITE("Stay away if you can.");
        return n;
    }
    if ((combined & EUI_FLAG_INVESTIGATION) || cls == EUI_CLASS_INVESTIGATION) {
        WRITE("This is a hacking or testing tool nearby.");
        WRITE("Could attack your phone or accounts. Move away.");
        return n;
    }

    if (cls == EUI_CLASS_TRACKER) {
        if (d->is_airtag) {
            WRITE("Find My tracker nearby.");
            WRITE("Common item tracker. Not a sign of danger.");
        } else {
            WRITE("Item tracker nearby (Tile, SmartTag, etc).");
            WRITE("Common and harmless. Just so you know.");
        }
        return n;
    }

    if (cls == EUI_CLASS_DRONE) {
        WRITE("Drone broadcasting nearby.");
        int sep = drone_op_separation_m(&d->drone);
        if (sep >= 0)
            WRITE("Pilot ~%dm from the drone.", sep);
        else
            WRITE("Receive-only. Not a threat to you.");
        return n;
    }

    if ((combined & EUI_FLAG_SURVEILLANCE) || cls == EUI_CLASS_SURVEILLANCE_CAM) {
        WRITE("Surveillance camera or sensor nearby.");
        if (combined & EUI_FLAG_FCC_COVERED)
            WRITE("From a brand on the FCC restricted list.");
        else
            WRITE("Could be recording video or audio.");
        return n;
    }
    if (cls == EUI_CLASS_ACCESS_CONTROL) {
        WRITE("Smart lock or access reader nearby.");
        WRITE("Normal in offices and apartments.");
        return n;
    }

    if ((combined & EUI_FLAG_DEV_MODULE) || cls == EUI_CLASS_DEV_MODULE) {
        WRITE("Looks like a raw chip module, not a finished product.");
        WRITE("Unusual but not always hostile.");
        return n;
    }
    if ((combined & EUI_FLAG_MAKER) || cls == EUI_CLASS_MAKER_BOARD) {
        WRITE("Looks like a homemade electronics project.");
        WRITE("Hobby gear, not usually a threat.");
        return n;
    }

    switch (cls_certain) {
    case EUI_CLASS_PHONE:
    case EUI_CLASS_MOBILE:
        WRITE("Looks like a phone nearby.");
        break;
    case EUI_CLASS_TABLET:
        WRITE("Looks like a tablet nearby.");
        break;
    case EUI_CLASS_LAPTOP:
        WRITE("Looks like a laptop nearby.");
        break;
    case EUI_CLASS_AUDIO:
        WRITE("Looks like wireless headphones or a speaker.");
        break;
    case EUI_CLASS_WEARABLE:
        WRITE("Looks like a smartwatch or fitness band.");
        break;
    case EUI_CLASS_IOT_HUB:
        WRITE("Smart home hub nearby (Alexa, Nest, etc).");
        break;
    case EUI_CLASS_IOT_LEAF:
        WRITE("Smart home gadget nearby (bulb, sensor, etc).");
        break;
    case EUI_CLASS_MEDICAL:
        WRITE("Looks like a medical device.");
        WRITE("Common: glucose, blood pressure, hearing.");
        break;
    case EUI_CLASS_VEHICLE:
        WRITE("Looks like a car or OBD scan tool.");
        break;
    case EUI_CLASS_BEACON:
        WRITE("Looks like a store or museum location beacon.");
        break;
    case EUI_CLASS_STANDARDS:
        WRITE("Looks like a standards device (Matter / FIDO / mesh).");
        break;
    default:
        if (d->vendor[0]) {
            WRITE("Device from %s.", d->vendor);
        } else if (d->name[0]) {
            WRITE("Device named \"%s\".", d->name);
        } else {
            WRITE("Unrecognized Bluetooth device.");
        }
        break;
    }

    if (n < 2) {

        if (d->is_airtag) {

        } else if (d->vendor[0] && d->name[0]) {
            WRITE("%.28s — %.28s", d->vendor, d->name);
        }
    }

    #undef WRITE
    return n;
}

uint8_t ble_effective_class(const ble_device_t *d)
{
    if (!d) return EUI_CLASS_UNKNOWN;
    switch (d->class_source) {
    case BLE_CLASS_SRC_MFG_RULE:      return d->mfg_rule_class;
    case BLE_CLASS_SRC_UUID128:       return d->uuid128_class;
    case BLE_CLASS_SRC_UUID16:        return d->uuid16_class;
    case BLE_CLASS_SRC_APPLE_SUBTYPE: return d->apple_subtype_class;
    case BLE_CLASS_SRC_MS_SUBTYPE:    return d->ms_subtype_class;
    case BLE_CLASS_SRC_BT_COMPANY:    return d->bt_company_class;
    case BLE_CLASS_SRC_MAC_OUI:       return d->device_class;
    case BLE_CLASS_SRC_NAME_RULE:     return d->name_rule_class;
    case BLE_CLASS_SRC_DRONE_RID:     return EUI_CLASS_DRONE;
    default:                          return EUI_CLASS_UNKNOWN;
    }
}

uint8_t ble_effective_class_certain(const ble_device_t *d)
{
    if (!d) return EUI_CLASS_UNKNOWN;
    if (d->class_conf < BLE_CLASS_CONF_OK) return EUI_CLASS_UNKNOWN;
    return ble_effective_class(d);
}

static char conf_letter(uint8_t c)
{
    if (c >= BLE_CLASS_CONF_HIGH) return 'H';
    if (c >= BLE_CLASS_CONF_OK)   return 'M';
    if (c > 0)                     return 'L';
    return '-';
}

char ble_class_conf_letter(const ble_device_t *d)
{
    return d ? conf_letter(d->class_conf) : '-';
}

char ble_vendor_conf_letter(const ble_device_t *d)
{
    return d ? conf_letter(d->vendor_conf) : '-';
}

const char *ble_class_source_label(uint8_t source)
{
    switch (source) {
    case BLE_CLASS_SRC_MFG_RULE:      return "catalog";
    case BLE_CLASS_SRC_UUID128:       return "uuid128";
    case BLE_CLASS_SRC_APPLE_SUBTYPE: return "apple";
    case BLE_CLASS_SRC_MS_SUBTYPE:    return "ms-cdp";
    case BLE_CLASS_SRC_BT_COMPANY:    return "bt-cid";
    case BLE_CLASS_SRC_MAC_OUI:       return "mac-oui";
    case BLE_CLASS_SRC_NAME_RULE:     return "name";
    case BLE_CLASS_SRC_DRONE_RID:     return "drone-rid";
    default:                           return "-";
    }
}
