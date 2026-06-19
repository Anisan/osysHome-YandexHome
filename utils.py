import json
import hashlib
import base64
import secrets

from app.core.lib.object import getProperty
from app.core.lib.converters.color_value import normalize_hex_input


def generate_pkce_pair():
    """Сгенерировать code_verifier и code_challenge (S256) для OAuth PKCE."""
    verifier = secrets.token_urlsafe(48)
    if len(verifier) < 43:
        verifier += secrets.token_urlsafe(8)
    verifier = verifier[:128]
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return verifier, challenge


def _hex_to_yandex_int(hex_str):
    try:
        r, g, b = normalize_hex_input(hex_str)
        return (r << 16) + (g << 8) + b
    except ValueError:
        return None


def get_yandex_rgb(prop_name, raw_value=None):
    """Читает цвет через getProperty(..., 'rgb'/'hex') и возвращает int для API Яндекса."""
    rgb = getProperty(prop_name, 'rgb')
    if isinstance(rgb, dict) and 'r' in rgb:
        r, g, b = int(rgb['r']), int(rgb['g']), int(rgb['b'])
        return (r << 16) + (g << 8) + b
    hex_color = getProperty(prop_name, 'hex')
    if isinstance(hex_color, str):
        parsed = _hex_to_yandex_int(hex_color)
        if parsed is not None:
            return parsed
    value = raw_value if raw_value is not None else getProperty(prop_name, 'value')
    if value is None or value == '' or value == 'None':
        return 0
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        parsed = _hex_to_yandex_int(value)
        if parsed is not None:
            return parsed
    return 0


def get_yandex_hsv(prop_name, raw_value=None):
    """Читает цвет через getProperty(..., 'hsv') и возвращает {h, s, v} для API Яндекса."""
    hsv_data = getProperty(prop_name, 'hsv')
    if isinstance(hsv_data, dict) and 'hsv' in hsv_data:
        parts = [int(float(v.strip())) for v in str(hsv_data['hsv']).split(',')]
        return {'h': parts[0], 's': parts[1], 'v': parts[2]}
    value = raw_value if raw_value is not None else getProperty(prop_name, 'value')
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            pass
    if isinstance(value, dict) and {'h', 's', 'v'} <= set(value.keys()):
        return {
            'h': int(value.get('h', 0)),
            's': int(value.get('s', 100)),
            'v': int(value.get('v', 50)),
        }
    return {'h': 0, 's': 100, 'v': 50}


def yandex_rgb_to_property_value(value):
    """Конвертирует int RGB из API Яндекса в hex для setProperty (type=color)."""
    value = int(value)
    r, g, b = (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF
    return f'#{r:02X}{g:02X}{b:02X}'


def yandex_hsv_to_property_value(value):
    """Конвертирует HSV из API Яндекса в формат write для type=color."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            value = {}
    if not isinstance(value, dict):
        value = {}
    return {
        'hsv': f"{int(value.get('h', 0))},{int(value.get('s', 100))},{int(value.get('v', 50))}"
    }
