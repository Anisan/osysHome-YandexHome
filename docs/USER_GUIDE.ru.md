# YandexHome - Руководство пользователя

![YandexHome Icon](../static/YandexHome.png "Плагин YandexHome")

## Назначение

`YandexHome` подключает устройства osysHome к экосистеме Яндекса, чтобы ими можно было управлять через Алису и приложение Дом с Алисой.

После настройки модуль:

- публикует список ваших устройств в Яндекс;
- отдает текущее состояние устройств по запросу;
- принимает команды от Алисы и применяет их к свойствам объектов osysHome;
- при включенном `Reportable` отправляет изменения состояния в Яндекс callback API.

---

## Что нужно до начала

- Домен с доступом по HTTPS.
- Валидный SSL-сертификат (например, Let's Encrypt).
- Созданный навык типа "Умный дом" в Yandex Dialogs.

> [!IMPORTANT]
> Без HTTPS и корректно настроенного OAuth Яндекс не сможет связать аккаунт.

---

## Настройка навыка в Яндексе

1. Откройте `https://dialogs.yandex.ru/`.
2. Создайте навык: `Создать навык -> Создать диалог -> Умный дом`.
3. Заполните название навыка (любое удобное).
4. Укажите `Endpoint URL`:

```text
https://<ваш-домен>/YandexHome
```

5. Включите приватный сценарий:
- `Не показывать в каталоге` -> включить;
- `Официальный навык` -> выключить (`нет`);
- остальные публичные поля (описания, иконка) можно заполнить минимально.
6. Откройте раздел `Авторизация` и нажмите `Создать`.
7. Сохраните `Client ID` и `Client Secret`.
8. В OAuth-настройках навыка укажите:

```text
URL авторизации: https://<ваш-домен>/YandexHome/auth/
URL токена:      https://<ваш-домен>/YandexHome/token/
```

9. Выполните шаги публикации: `Сохранить -> Сохранить -> На модерацию -> Опубликовать`.

> [!NOTE]
> Для приватного навыка модерация обычно проходит быстро.

10. Скопируйте `Skill ID` из карточки навыка.

---

## Настройка модуля в osysHome

Откройте `/admin/YandexHome`, кнопку `Settings`, и заполните:

| Поле | Описание |
| --- | --- |
| `Username` | Логин, который вводится на странице OAuth `/YandexHome/auth/` |
| `Password` | Пароль для OAuth-логина |
| `Client ID` | OAuth Client ID из Yandex Dialogs |
| `Client secret` | OAuth Client Secret из Yandex Dialogs |
| `Client key` | OAuth токен для callback API Яндекса (нужен для reportable/discovery) |
| `Skill ID` | ID навыка (нужен для callback API Яндекса) |

> [!TIP]
> В форме есть генераторы для `Client ID` и `Client secret`, но обычно лучше использовать значения, выданные Яндексом.

---

## Добавление устройства

1. Нажмите `Add device`.
2. Заполните общие поля:
- `Name`
- `Description`
- `Type` (например, `light`, `switch`, `sensor.*`)
- `Room`
3. При необходимости заполните расширенные поля: `Manufacturer`, `Model`, `SW version`, `HW version`.
4. Нажмите `Add capability` и добавьте нужные возможности/свойства.
5. Для каждой capability укажите:
- объект osysHome (`linked_object`);
- свойство объекта (`linked_property`);
- опционально `Reportable`.
6. Нажмите `Save`.

После сохранения модуль запускает discovery callback в Яндекс, чтобы обновить список устройств.

---

## Как выбирать capability

В модуле есть два типа сущностей:

- `capabilities` (например, `on`, `brightness`, `temperature`, `mode`);
- `properties` (например, `*_sensor`, `*_event`).

Практическое правило выбора:

- если Алиса должна уметь управлять параметром, выбирайте capability из `capabilities` (например, `on`, `brightness`, `fan_speed`, `thermostat`);
- если нужно только отдавать показания/события, используйте `properties` (`*_sensor`, `*_event`).

### Минимальный рекомендуемый набор

| Сценарий | Что добавить |
| --- | --- |
| Лампа | `on`, опционально `brightness`, `rgb`, `temperature_k`, `color_scene` |
| Розетка/реле | `on` |
| Датчик температуры/влажности | `temperature_sensor`, `humidity_sensor` |
| Датчик движения/дыма/газа | `motion_event`, `smoke_event`, `gas_event` |
| Климат/увлажнитель | `on`, `temperature`, `humidity`, `fan_speed`, `ionization` |
| Шторы/клапан | `open` или `open_event` (в зависимости от модели устройства) |

### Как настраивать параметры capability

- `range`: задавайте `min`, `max`, `precision` так, чтобы они соответствовали реальному диапазону свойства в объекте osysHome.
- `mode`: оставляйте только поддерживаемые режимы в `modes`, чтобы Алиса не отправляла неподдерживаемые значения.
- `color_scene`: оставляйте только те сцены, которые действительно обрабатываются вашей логикой.
- `split` (для `on`): используйте, если требуется особая логика обработки в вашем объекте.

### Когда включать Reportable

- включайте `Reportable`, если хотите push-обновления состояния в Яндекс без ожидания `query`;
- не включайте `Reportable`, если значение редко меняется или не критично для мгновенного отображения.

> [!IMPORTANT]
> `Reportable` работает только при заполненных `Client key` и `Skill ID`.

### Полезные ссылки по capability в документации Яндекса

- Типы capability: [Capability types](https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/capability-types)
- Типы property: [Property types](https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/properties-types)
- Устройства и их типы: [Device types](https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/device-type)
- Общая модель API умного дома: [Smart Home API concepts](https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/)

---

## Проверка интеграции

Чек-лист:

- [ ] Открывается `https://<ваш-домен>/YandexHome/v1.0` и отвечает `OK`.
- [ ] Привязка аккаунта проходит через `/YandexHome/auth/`.
- [ ] Вкладка `Тестирование` в Yandex Dialogs проходит связку аккаунта с `Username`/`Password` из настроек модуля.
- [ ] После привязки Яндекс получает устройства.
- [ ] Команды Алисы меняют значения свойств объектов osysHome.
- [ ] При `Reportable=true` изменения отправляются в callback API Яндекса.

---

## Типовые проблемы

### 1. Не проходит связка аккаунта

Проверьте:

- совпадают ли `Client ID`/`Client secret` в osysHome и Yandex Dialogs;
- корректны ли URL `/YandexHome/auth/` и `/YandexHome/token/`;
- работает ли HTTPS без ошибок сертификата;
- правильные ли `Username`/`Password` заданы в настройках модуля.

### 2. Устройства не появляются в приложении Яндекса

Проверьте:

- заполнены ли `Skill ID` и `Client key`;
- есть ли хотя бы одна capability у устройства;
- сохранилось ли устройство без ошибок;
- отправляется ли callback discovery после сохранения.

### 3. Команда приходит, но устройство не меняется

Проверьте:

- правильно ли выбраны `linked_object` и `linked_property`;
- существует ли свойство у объекта в osysHome;
- совместим ли тип значения (число/строка/булево) с вашей логикой объекта.

> [!WARNING]
> OAuth authorization code действует очень коротко (около 10 секунд). Если обмен кода на токен задержан, связка не пройдет.

---

## Ограничения и нюансы

- Access token сохраняется без TTL в кэше модуля, пока не выполнен `unlink`.
- Для callback-операций (`reportable`, `discovery`) обязательны `Client key` и `Skill ID`.
- Удаление устройства в админке также вызывает удаление устройства в облаке Яндекса через API.

---

## См. также

- [Техническая документация](TECHNICAL_REFERENCE.ru.md)
- [Индекс модуля](index.ru.md)
- Официальная документация Яндекс Умного дома: [https://yandex.ru/dev/dialogs/smart-home/doc/ru/](https://yandex.ru/dev/dialogs/smart-home/doc/ru/)
- Протокол API (запрос/ответ): [Protocol](https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/platform-protocol)
- Ошибки и коды: [Error codes](https://yandex.ru/dev/dialogs/smart-home/doc/ru/reference/errors)
- OAuth и связка аккаунтов: [Account linking](https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/authorization)
