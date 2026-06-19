# YandexHome - Yandex Smart Home Integration

![YandexHome Icon](static/YandexHome.png)

Integration with Yandex Smart Home (Yandex Alice) for controlling smart home devices via voice commands and the Yandex app.

## Description

The `YandexHome` module integrates osysHome with Yandex Smart Home. It enables voice control via Alice, maps osysHome object properties to Yandex device capabilities, and synchronizes state in real time.

## Main Features

- **Voice control** via Yandex Alice
- **Device types**: lights, switches, sensors, thermostats, etc.
- **OAuth authentication** for account linking
- **Device discovery** and state change notifications
- **Binding** osysHome properties to Yandex device capabilities

## Admin Panel

- View and group devices by room
- Configure types, capabilities, and object bindings
- Skill and OAuth token settings

## Technical Details

- **Protocol**: Yandex Smart Home API
- **Authentication**: OAuth 2.0
- **Category**: App
- **Actions**: `search`
- **Version**: 0.2

## Documentation

- [docs/index.md](docs/index.md) — table of contents
- [docs/SETUP.md](docs/SETUP.md) — skill setup, module fields, OAuth tokens

## Author

osysHome Team

## License

See the main osysHome project license
