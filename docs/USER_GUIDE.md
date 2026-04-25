# YandexHome - User Guide

![YandexHome Icon](../static/YandexHome.png "YandexHome plugin")

## Purpose

`YandexHome` connects osysHome devices to Yandex Smart Home, so they can be controlled from Alice and the Yandex Home app.

After setup, the module:

- publishes your devices to Yandex;
- returns current device state on query;
- receives Alice commands and applies them to osysHome object properties;
- sends state updates to Yandex callback API when `Reportable` is enabled.

---

## Prerequisites

- A public domain with HTTPS.
- A valid SSL certificate (for example, Let's Encrypt).
- A Yandex Dialogs skill created as "Smart Home".

> [!IMPORTANT]
> Without HTTPS and correct OAuth settings, account linking will fail.

---

## Yandex Skill Setup

1. Open `https://dialogs.yandex.ru/`.
2. Create a skill: `Create skill -> Create dialog -> Smart Home`.
3. Fill in skill name (any name is fine).
4. Set `Endpoint URL`:

```text
https://<your-domain>/YandexHome
```

5. Configure private skill behavior:
- enable `Do not show in catalog`;
- set `Official skill` to `No`;
- other public profile fields (description, icon) can be minimal.
6. Open `Authorization` and click `Create`.
7. Save generated `Client ID` and `Client Secret`.
8. Configure OAuth URLs:

```text
Authorization URL: https://<your-domain>/YandexHome/auth/
Token URL:         https://<your-domain>/YandexHome/token/
```

9. Complete publication flow: `Save -> Save -> Send to moderation -> Publish`.

> [!NOTE]
> For a private skill, moderation is usually fast.

10. Copy `Skill ID` from the skill card.

---

## Module Setup in osysHome

Open `/admin/YandexHome`, click `Settings`, and fill in:

| Field | Description |
| --- | --- |
| `Username` | Login used on OAuth page `/YandexHome/auth/` |
| `Password` | Password used on OAuth page |
| `Client ID` | OAuth Client ID from Yandex Dialogs |
| `Client secret` | OAuth Client Secret from Yandex Dialogs |
| `Client key` | OAuth token for Yandex callback API (required for reportable/discovery) |
| `Skill ID` | Yandex skill ID (required for callback API) |

> [!TIP]
> The form can generate random `Client ID` and `Client secret`, but production setups should usually use values issued by Yandex.

---

## Adding a Device

1. Click `Add device`.
2. Fill basic fields:
- `Name`
- `Description`
- `Type` (for example, `light`, `switch`, `sensor.*`)
- `Room`
3. Optionally fill advanced fields: `Manufacturer`, `Model`, `SW version`, `HW version`.
4. Click `Add capability`.
5. For each capability, set:
- osysHome object (`linked_object`);
- object property (`linked_property`);
- optional `Reportable`.
6. Click `Save`.

After save, the module triggers Yandex discovery callback to refresh the cloud device list.

---

## Choosing Capabilities

The module works with two groups:

- `capabilities` (for example, `on`, `brightness`, `temperature`, `mode`);
- `properties` (for example, `*_sensor`, `*_event`).

Practical selection rule:

- if Alice must control the parameter, use `capabilities` (for example, `on`, `brightness`, `fan_speed`, `thermostat`);
- if you only need telemetry/events, use `properties` (`*_sensor`, `*_event`).

### Minimal recommended sets

| Scenario | Add these |
| --- | --- |
| Light | `on`, optionally `brightness`, `rgb`, `temperature_k`, `color_scene` |
| Socket/relay | `on` |
| Temperature/humidity sensor | `temperature_sensor`, `humidity_sensor` |
| Motion/smoke/gas sensor | `motion_event`, `smoke_event`, `gas_event` |
| Climate/humidifier | `on`, `temperature`, `humidity`, `fan_speed`, `ionization` |
| Curtain/valve | `open` or `open_event` (depending on your model) |

### Capability parameter tuning

- `range`: configure `min`, `max`, `precision` to match the real osysHome property range.
- `mode`: keep only supported values in `modes`, so Alice does not send unsupported options.
- `color_scene`: keep only scenes your object logic can process.
- `split` (for `on`): use if your object requires special on/off processing.

### When to enable Reportable

- enable `Reportable` if you need push updates to Yandex without waiting for `query`;
- keep it disabled if the value rarely changes or instant cloud sync is not required.

> [!IMPORTANT]
> `Reportable` works only when `Client key` and `Skill ID` are configured.

### Useful Yandex capability references

- Capability types: [Capability types](https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/capability-types)
- Property types: [Property types](https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/properties-types)
- Device types: [Device types](https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/device-type)
- Smart Home API concepts: [Concepts](https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/)

---

## Integration Validation

Checklist:

- [ ] `https://<your-domain>/YandexHome/v1.0` returns `OK`.
- [ ] Account linking works through `/YandexHome/auth/`.
- [ ] In Yandex Dialogs `Testing` tab, account linking succeeds with module `Username`/`Password`.
- [ ] Yandex receives your devices after linking.
- [ ] Alice commands change osysHome property values.
- [ ] With `Reportable=true`, state changes are pushed to Yandex callback API.

---

## Common Problems

### 1. Account linking fails

Check:

- `Client ID`/`Client secret` match between osysHome and Yandex Dialogs;
- OAuth URLs `/YandexHome/auth/` and `/YandexHome/token/` are correct;
- HTTPS certificate is valid;
- module `Username`/`Password` are correct.

### 2. Devices are missing in Yandex app

Check:

- `Skill ID` and `Client key` are configured;
- device has at least one capability;
- device save request succeeds;
- discovery callback runs after save.

### 3. Commands are accepted but no real change happens

Check:

- `linked_object` and `linked_property` are mapped correctly;
- target property exists in osysHome;
- value type (number/string/boolean) is compatible with your object logic.

> [!WARNING]
> OAuth authorization code lifetime is very short (about 10 seconds). Delays during code-to-token exchange can break linking.

---

## Limitations and Notes

- Access tokens are cached without TTL until `unlink` is called.
- Callback features (`reportable`, `discovery`) require both `Client key` and `Skill ID`.
- Deleting a device in admin UI also calls Yandex cloud device delete API.

---

## See Also

- [Technical Reference](TECHNICAL_REFERENCE.md)
- [Module Index](index.md)
- Official Yandex Smart Home docs: [https://yandex.ru/dev/dialogs/smart-home/doc/ru/](https://yandex.ru/dev/dialogs/smart-home/doc/ru/)
- API protocol details: [Protocol](https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/platform-protocol)
- Error codes: [Error codes](https://yandex.ru/dev/dialogs/smart-home/doc/ru/reference/errors)
- OAuth and account linking: [Account linking](https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/authorization)
