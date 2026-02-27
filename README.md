# YandexHome - Yandex Smart Home Integration

![YandexHome Icon](static/YandexHome.png)

Integration with Yandex Smart Home (Yandex Alice) for controlling smart home devices via voice commands and Yandex app.

## Description

The `YandexHome` module provides integration with Yandex Smart Home platform for the osysHome platform. It enables voice control of smart home devices through Yandex Alice voice assistant.

## Main Features

- ✅ **Voice Control**: Control devices via Yandex Alice
- ✅ **Device Types**: Support for various device types (lights, switches, sensors, etc.)
- ✅ **OAuth Authentication**: Secure OAuth-based authentication
- ✅ **Device Discovery**: Automatic device discovery and registration
- ✅ **Property Mapping**: Map osysHome properties to Yandex device capabilities
- ✅ **State Synchronization**: Real-time state synchronization

## Admin Panel

The module provides an admin interface for:
- Viewing Yandex devices
- Configuring device settings
- Managing device capabilities
- Linking devices to osysHome objects

## Setup Requirements

- Domain name
- SSL certificate (Let's Encrypt recommended)
- Yandex Dialog skill configuration

## Configuration

- **User ID**: Yandex user identifier
- **User Password**: User password for authentication
- **Client ID**: Yandex Dialog skill client ID
- **Client Secret**: Yandex Dialog skill client secret
- **Client Key**: Client key for API
- **Skill ID**: Yandex Dialog skill ID

## Setup Instructions

1. Visit https://dialogs.yandex.ru/
2. Create new skill -> Create dialog -> Smart Home
3. Set endpoint URL: `https://your-domain/YandexHome`
4. Configure OAuth URLs:
   - Authorization: `https://your-domain/YandexHome/auth/`
   - Token: `https://your-domain/YandexHome/token/`
5. Enter credentials in module settings
6. Test connection in Yandex Dialog testing panel

## Usage

### Adding Device

1. Navigate to YandexHome module
2. Click "Add Device"
3. Select osysHome object
4. Configure device type and capabilities
5. Device available in Yandex app

## Technical Details

- **Protocol**: Yandex Smart Home API
- **Authentication**: OAuth 2.0
- **Device Types**: Lights, switches, sensors, thermostats, etc.
- **Capabilities**: on/off, brightness, color, temperature, etc.

## Version

Current version: **0.2**

## Category

App

## Actions

The module provides the following actions:
- `search` - Search devices

## Requirements

- Flask
- SQLAlchemy
- SSL certificate
- Domain name
- osysHome core system

## Author

osysHome Team

## License

See the main osysHome project license

