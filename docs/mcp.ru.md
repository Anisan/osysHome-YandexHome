# MCP — YandexHome

Плагин публикует виртуальные устройства osysHome в Яндекс Умный дом (Алиса). Привязки к свойствам объектов живут внутри карты `capability`.

## Plugin notes

- Коллекция `devices` — устройства для Alice; bindings задаются в traits внутри `capability`.
- `capability` — объект `instance_name → trait` (обычно ключ = тип, например `on`, `brightness`).
- В trait нужны `type`, `linked_object`, `linked_property`; `reportable` включает push состояния в Yandex.
- Типы устройств и instance берите через `get_device_types` — неизвестные значения отклоняются.
- `config` генерируется при сохранении; через upsert не пишите.
- После create/update/delete вызывается discovery (нужны `CLIENT_KEY`, `SKILL_ID`, `USER_ID`).
- `reportable` требует `CLIENT_KEY` и `SKILL_ID`; без них Alice работает через query/action.

## Collections

| ID | binding_mode | writable | writable_fields | list_filters |
|----|--------------|----------|-----------------|--------------|
| `devices` | `property` | yes | `title`, `type`, `room`, `description`, `manufacturer`, `model`, `sw_version`, `hw_version`, `capability` | `query` |

### Поля entity (devices)

| поле | writable | описание |
|------|----------|----------|
| `title` | да | Имя устройства для Алисы |
| `type` | да | Тип устройства Yandex (`light`, `socket`, …) |
| `room` | да | Комната |
| `description` | да | Описание |
| `manufacturer`, `model`, `sw_version`, `hw_version` | да | device_info |
| `capability` | да | Карта traits / bindings |
| `config` | read-only | Сгенерированный payload для Yandex API |
| `id` | read-only | ID в БД |

### Структура capability trait

```json
{
  "on": {
    "type": "on",
    "description": "Turn on/off",
    "linked_object": "Lamp1",
    "linked_property": "status",
    "reportable": true
  },
  "brightness": {
    "type": "brightness",
    "linked_object": "Lamp1",
    "linked_property": "brightness",
    "reportable": true,
    "min": 1,
    "max": 100,
    "precision": 1
  }
}
```

Опциональные поля: `min`/`max`/`precision` (range), `modes`, `scenes`, `split`.

## Операции (invoke)

| operation | Описание |
|-----------|----------|
| `discovery` | Callback discovery — обновить список устройств в Яндексе |
| `get_device_types` | Список допустимых `devices_types` и `devices_instance` |
| `get_integration_status` | Готовность OAuth / callback (без секретов) |

## Промпты

| name | Назначение |
|------|------------|
| `osys_yandexhome_entity_authoring` | Собрать payload устройства по схеме |
| `osys_yandexhome_binding` | Привязать `object.property` к capability trait |

## Примеры

### Список устройств

```json
{
  "plugin": "YandexHome",
  "action": "list_entities",
  "args": {
    "collection": "devices",
    "query": "lamp"
  }
}
```

### Справочник типов

```json
{
  "plugin": "YandexHome",
  "action": "invoke",
  "args": {
    "operation": "get_device_types",
    "params": {}
  }
}
```

### Создать лампу с on + brightness

```json
{
  "plugin": "YandexHome",
  "action": "upsert_entity",
  "args": {
    "collection": "devices",
    "payload": {
      "title": "Люстра",
      "type": "light.ceiling",
      "room": "Гостиная",
      "capability": {
        "on": {
          "type": "on",
          "linked_object": "LivingLight",
          "linked_property": "status",
          "reportable": true
        },
        "brightness": {
          "type": "brightness",
          "linked_object": "LivingLight",
          "linked_property": "brightness",
          "reportable": true,
          "min": 1,
          "max": 100,
          "precision": 1
        }
      }
    }
  }
}
```

### Статус интеграции

```json
{
  "plugin": "YandexHome",
  "action": "invoke",
  "args": {
    "operation": "get_integration_status",
    "params": {}
  }
}
```

### Discovery после смены токена

```json
{
  "plugin": "YandexHome",
  "action": "invoke",
  "args": {
    "operation": "discovery",
    "params": {}
  }
}
```

## Важно

- Перед upsert вызывайте `validate_entity`, особенно при сборке `capability`.
- Для управления Alice нужны навыки Умного дома + HTTPS endpoint `/YandexHome`.
- `Reportable` без `CLIENT_KEY`/`SKILL_ID` не отправляет state callback.
