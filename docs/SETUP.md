# YandexHome — setup

## Requirements

- Domain name
- HTTPS SSL certificate (Let's Encrypt recommended)
- Smart Home skill in [Yandex Dialogs](https://dialogs.yandex.ru/)

## Yandex Dialog skill setup

1. Open https://dialogs.yandex.ru/ → Create skill → Create dialog → Smart Home.
2. Set **Endpoint URL**: `https://your-domain/YandexHome`
3. Enable private skill settings as needed.
4. **Account linking** tab → Create:
   - set **App ID** and **App secret**;
   - **Authorization URL**: `https://your-domain/YandexHome/auth/`
   - **Token URL**: `https://your-domain/YandexHome/token/`
5. Save → Submit for moderation → Publish.
6. On the **Testing** tab, link accounts using **Username** and **Password** from osysHome module settings.

## Module fields

| Field | Description |
| --- | --- |
| **Username** | User ID for account linking |
| **Password** | Password for account linking |
| **Client ID** | App ID from skill account linking |
| **Client secret** | App secret from skill account linking |
| **Client key** | Yandex Dialogs OAuth token for state notifications |
| **Skill ID** | Skill identifier (General tab in developer console) |

## OAuth tokens for notifications

To push device state changes (`reportable` properties), the module calls:

```http
POST https://dialogs.yandex.net/api/v1/skills/{skill_id}/callback/state
Authorization: OAuth <token>
```

The token must come from the **Yandex account that created the skill** (not the account-linking Client ID / Client secret).

Yandex docs: https://yandex.ru/dev/dialogs/smart-home/doc/en/reference-alerts/resources-alerts.html#oauth

### Client key — quick setup

1. Sign in to Yandex with the account that owns the skill.
2. Open:

   https://oauth.yandex.ru/authorize?response_type=token&client_id=c473ca268cd749d3a8371351a8f2bcbd

3. Click Allow.
4. Copy the token from the page that opens after authorization (the key button in module settings opens the same page).
5. Paste into **Client key**.

Renew manually when the token expires. Yandex Dialogs' public OAuth app has no `client_secret`, so refresh-token auto-renewal is not available.

### Client key — via authorization code (PKCE)

1. Sign in to Yandex with the account that owns the skill.
2. In module settings, click **via PKCE** next to Client key.
3. Click Allow and copy the code from the Yandex page (you can paste the full redirect URL).
4. Paste into **Authorization code** and click **Exchange for tokens**.
5. **Client key** is filled automatically; save settings.

On HTTP 401/403 the module shows a notification with a link to obtain a new token — update **Client key** manually.

## Adding devices

1. Open YandexHome in osysHome admin.
2. Click Add device.
3. Link osysHome objects and properties.
4. Configure device type and capabilities.
5. Refresh device list in the Yandex Home app.
