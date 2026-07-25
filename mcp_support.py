"""MCP integration helpers for YandexHome plugin."""

from __future__ import annotations

import json
from typing import List, Optional, Set, Tuple

from sqlalchemy import delete, or_

from app.core.lib.mcp_contract import (
    build_plugin_mcp_descriptors,
    revision_from_dict,
    validate_entity_payload,
)
from app.core.lib.plugin_binding import (
    remove_property_link,
    sync_property_link,
    validate_object_property_exists,
)
from app.database import row2dict, session_scope

from plugins.YandexHome.constants import devices_instance, devices_types
from plugins.YandexHome.models.YandexHomeDevices import YaHomeDevice

DEVICES = "devices"
PLUGIN_NAME = "YandexHome"

_DEVICE_WRITABLE_FIELDS = (
    "title",
    "type",
    "room",
    "description",
    "manufacturer",
    "model",
    "sw_version",
    "hw_version",
    "capability",
)
_DEVICE_READONLY_FIELDS = ("id", "config")

_PLUGIN_NOTES = [
    "YandexHome exposes osysHome objects to Alice / Yandex Smart Home as virtual devices.",
    "Collection devices: one Yandex device mapped to one or more osysHome property bindings via capability.",
    "capability is an object keyed by instance name (usually same as trait type, e.g. on, brightness).",
    "Each capability trait needs type, linked_object, linked_property; reportable enables push state to Yandex.",
    "Call get_device_types before inventing type or capability keys — unknown values are rejected.",
    "config is generated on save from generateConfig; do not write it via upsert.",
    "After create/update/delete the plugin runs discovery callback (requires CLIENT_KEY + SKILL_ID + USER_ID).",
    "Reportable needs CLIENT_KEY and SKILL_ID; without them Alice still works via query/action polling.",
    "Prefer validate_entity before upsert when building capability maps.",
    "Use invoke discovery after manual config/token changes to refresh Yandex device list.",
]

_BINDING_PROMPT = "osys_yandexhome_binding"
_ENTITY_AUTHORING_PROMPT = "osys_yandexhome_entity_authoring"


def _plugin_instance():
    try:
        from app.core.main.PluginsHelper import plugins
        return plugins.get(PLUGIN_NAME, {}).get("instance")
    except Exception:
        return None


def mcp_capabilities() -> dict:
    return {
        "mcp_version": 1,
        "entities": True,
        "config_schema": True,
        "notes": list(_PLUGIN_NOTES),
        "collections": [
            {
                "id": DEVICES,
                "title": "Yandex Home Devices",
                "binding_mode": "property",
                "writable": True,
                "has_code": False,
                "list_filters": ["query"],
                "default_sort": "room asc, title asc, id asc",
                "writable_fields": list(_DEVICE_WRITABLE_FIELDS),
                "description": (
                    "Virtual devices published to Yandex Smart Home. "
                    "Bindings live inside capability traits (linked_object/linked_property)."
                ),
            },
        ],
        "operations": [
            "discovery",
            "get_device_types",
            "get_integration_status",
        ],
        "operation_schemas": {
            "discovery": {
                "description": "Notify Yandex Smart Home to refresh the device list (callback discovery)",
                "params": {"type": "object", "properties": {}},
            },
            "get_device_types": {
                "description": "List allowed device types and capability/property instances for capability maps",
                "params": {"type": "object", "properties": {}},
            },
            "get_integration_status": {
                "description": "Report whether OAuth/skill settings required for discovery and reportable are configured",
                "params": {"type": "object", "properties": {}},
            },
        },
    }


def mcp_config_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "USER_ID": {
                "type": "string",
                "description": "OAuth username used on /YandexHome/auth/ account linking",
            },
            "USER_PASSWORD": {"type": "string", "writeOnly": True},
            "CLIENT_ID": {
                "type": "string",
                "description": "OAuth client ID from Yandex Dialogs skill authorization",
            },
            "CLIENT_SECRET": {"type": "string", "writeOnly": True},
            "CLIENT_KEY": {
                "type": "string",
                "writeOnly": True,
                "description": "OAuth access token for Yandex callback API (discovery / reportable state)",
            },
            "SKILL_ID": {
                "type": "string",
                "description": "Yandex Dialogs skill ID for callback API",
            },
        },
        "additionalProperties": False,
    }


def _collection_meta(collection: str) -> dict:
    for item in mcp_capabilities()["collections"]:
        if item["id"] == collection:
            return item
    raise ValueError(f"Unsupported collection: {collection}")


def _parse_capability(value) -> dict:
    if value in (None, ""):
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError):
            return {}
    return {}


def _parse_config(value) -> Optional[dict]:
    if value in (None, ""):
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else None
        except (TypeError, ValueError):
            return None
    return None


def _reportable_links(capability: dict) -> Set[Tuple[str, str]]:
    links: Set[Tuple[str, str]] = set()
    for trait in capability.values():
        if not isinstance(trait, dict):
            continue
        if not trait.get("reportable"):
            continue
        obj = str(trait.get("linked_object") or "").strip()
        prop = str(trait.get("linked_property") or "").strip()
        if obj and prop:
            links.add((obj, prop))
    return links


def _sync_capability_links(old_capability: dict, new_capability: dict) -> None:
    old_links = _reportable_links(old_capability)
    new_links = _reportable_links(new_capability)
    for obj, prop in old_links - new_links:
        remove_property_link(PLUGIN_NAME, obj, prop)
    for obj, prop in new_links:
        ok, err = sync_property_link(PLUGIN_NAME, obj, prop)
        if not ok:
            raise ValueError(err or "property link validation failed")


def _device_to_dict(row: YaHomeDevice) -> dict:
    data = row2dict(row)
    data["capability"] = _parse_capability(row.capability)
    config = _parse_config(row.config)
    if config is not None:
        data["config"] = config
    return data


def _query_filter(query: str):
    like = f"%{query}%"
    return or_(
        YaHomeDevice.title.ilike(like),
        YaHomeDevice.description.ilike(like),
        YaHomeDevice.room.ilike(like),
        YaHomeDevice.capability.ilike(like),
        YaHomeDevice.type.ilike(like),
    )


def _merge_device_payload(payload: dict, entity_id=None) -> dict:
    merged = dict(payload or {})
    if entity_id in (None, ""):
        return merged
    try:
        current = mcp_get_entity(DEVICES, entity_id)
    except ValueError:
        return merged
    for field in _DEVICE_WRITABLE_FIELDS:
        if field not in merged and field in current:
            merged[field] = current[field]
    return merged


def _find_device_by_title(session, title: str, exclude_id=None):
    name = str(title or "").strip()
    if not name:
        return None
    query = session.query(YaHomeDevice).filter(YaHomeDevice.title == name)
    if exclude_id not in (None, ""):
        query = query.filter(YaHomeDevice.id != int(exclude_id))
    return query.order_by(YaHomeDevice.id).first()
    _collection_meta(collection)
    if collection == DEVICES:
        return {
            "type": "object",
            "description": (
                "Yandex Smart Home device. Bindings are inside capability traits, "
                "not top-level linked_object fields."
            ),
            "properties": {
                "id": {
                    "type": "integer",
                    "readOnly": True,
                    "description": "Database id (set by server on create)",
                },
                "title": {"type": "string", "description": "Device name shown to Alice"},
                "type": {
                    "type": "string",
                    "description": "Yandex device type key (see invoke get_device_types)",
                },
                "room": {"type": "string", "description": "Room name for Yandex Home"},
                "description": {"type": "string"},
                "manufacturer": {"type": "string"},
                "model": {"type": "string"},
                "sw_version": {"type": "string"},
                "hw_version": {"type": "string"},
                "capability": {
                    "type": "object",
                    "description": (
                        "Map of instance_name -> trait. Typical trait fields: "
                        "type, description, linked_object, linked_property, reportable, "
                        "and optional min/max/precision/modes/scenes/split."
                    ),
                },
                "config": {
                    "type": "object",
                    "readOnly": True,
                    "description": "Generated Yandex API payload; rewritten on every save",
                },
            },
            "required": ["title", "type"],
        }
    raise ValueError(f"Unsupported collection: {collection}")


def mcp_list_entities(collection: str, query: str = None, limit: int = 100) -> List[dict]:
    limit = max(1, min(int(limit or 100), 5000))
    if collection == DEVICES:
        with session_scope() as session:
            q = session.query(YaHomeDevice)
            if query:
                q = q.filter(_query_filter(query))
            rows = q.order_by(YaHomeDevice.room, YaHomeDevice.title, YaHomeDevice.id).limit(limit).all()
            return [_device_to_dict(row) for row in rows]
    raise ValueError(f"Unsupported collection: {collection}")


def mcp_get_entity(collection: str, entity_id) -> dict:
    with session_scope() as session:
        if collection == DEVICES:
            row = session.query(YaHomeDevice).filter(YaHomeDevice.id == int(entity_id)).one_or_none()
            if row is None:
                raise ValueError(f"Device not found: {entity_id}")
            return _device_to_dict(row)
    raise ValueError(f"Unsupported collection: {collection}")


def mcp_upsert_entity(collection: str, payload: dict, entity_id=None) -> dict:
    meta = _collection_meta(collection)
    if not meta.get("writable"):
        raise ValueError(f"Collection '{collection}' is read-only")
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    if collection != DEVICES:
        raise ValueError(f"Unsupported collection: {collection}")

    clean_payload = dict(payload)
    for field in _DEVICE_READONLY_FIELDS:
        clean_payload.pop(field, None)

    validation = mcp_validate_entity(collection, clean_payload, entity_id=entity_id)
    if not validation.get("ok"):
        raise ValueError(f"validation failed: {validation}")

    instance = _plugin_instance()
    with session_scope() as session:
        old_capability = {}
        if entity_id not in (None, ""):
            row = session.query(YaHomeDevice).filter(YaHomeDevice.id == int(entity_id)).one_or_none()
            if row is None:
                raise ValueError(f"Device not found: {entity_id}")
            old_capability = _parse_capability(row.capability)
        else:
            title = str(clean_payload.get("title") or "").strip()
            row = _find_device_by_title(session, title) if title else None
            if row is None:
                row = YaHomeDevice()
                session.add(row)

        if "title" in clean_payload:
            row.title = clean_payload.get("title")
        if "type" in clean_payload:
            row.type = clean_payload.get("type")
        if "room" in clean_payload:
            row.room = clean_payload.get("room")
        if "description" in clean_payload:
            row.description = clean_payload.get("description")
        if "manufacturer" in clean_payload:
            row.manufacturer = clean_payload.get("manufacturer")
        if "model" in clean_payload:
            row.model = clean_payload.get("model")
        if "sw_version" in clean_payload:
            row.sw_version = clean_payload.get("sw_version")
        if "hw_version" in clean_payload:
            row.hw_version = clean_payload.get("hw_version")

        new_capability = old_capability
        if "capability" in clean_payload:
            new_capability = _parse_capability(clean_payload.get("capability"))
            row.capability = json.dumps(new_capability, ensure_ascii=False)

        session.commit()
        session.refresh(row)

        _sync_capability_links(old_capability, new_capability)

        if instance is not None:
            row.config = json.dumps(instance.generateConfig(row), ensure_ascii=False)
            session.commit()
            session.refresh(row)
            instance.discovery()

        return _device_to_dict(row)


def mcp_delete_entity(collection: str, entity_id) -> bool:
    meta = _collection_meta(collection)
    if not meta.get("writable"):
        raise ValueError(f"Collection '{collection}' is read-only")

    if collection == DEVICES:
        instance = _plugin_instance()
        with session_scope() as session:
            row = session.query(YaHomeDevice).filter(YaHomeDevice.id == int(entity_id)).one_or_none()
            if row is None:
                raise ValueError(f"Device not found: {entity_id}")
            for obj, prop in _reportable_links(_parse_capability(row.capability)):
                remove_property_link(PLUGIN_NAME, obj, prop)
            if instance is not None:
                instance.delete_device(int(entity_id))
            session.execute(delete(YaHomeDevice).where(YaHomeDevice.id == int(entity_id)))
            session.commit()
            return True

    raise ValueError(f"Unsupported collection: {collection}")


def mcp_validate_entity_code(collection: str, code: str) -> dict:
    raise ValueError(f"Collection '{collection}' does not support code validation")


def mcp_run_entity_dry(collection: str, code: str, context: dict = None) -> dict:
    raise ValueError(f"Collection '{collection}' does not support dry-run code")


def _integration_status() -> dict:
    instance = _plugin_instance()
    if instance is None:
        raise ValueError("YandexHome plugin not loaded")
    config = instance.config or {}

    def _filled(key: str) -> bool:
        return bool(str(config.get(key) or "").strip())

    has_user = _filled("USER_ID")
    has_password = _filled("USER_PASSWORD")
    has_client_id = _filled("CLIENT_ID")
    has_client_secret = _filled("CLIENT_SECRET")
    has_client_key = _filled("CLIENT_KEY")
    has_skill_id = _filled("SKILL_ID")
    return {
        "plugin_loaded": True,
        "account_linking_ready": has_user and has_password and has_client_id and has_client_secret,
        "callback_ready": has_client_key and has_skill_id and has_user,
        "configured": {
            "USER_ID": has_user,
            "USER_PASSWORD": has_password,
            "CLIENT_ID": has_client_id,
            "CLIENT_SECRET": has_client_secret,
            "CLIENT_KEY": has_client_key,
            "SKILL_ID": has_skill_id,
        },
    }


def mcp_invoke(operation: str, params: dict = None) -> dict:
    params = params or {}
    if operation == "discovery":
        instance = _plugin_instance()
        if instance is None:
            raise ValueError("YandexHome plugin not loaded")
        instance.discovery()
        return {"ok": True, "operation": operation}
    if operation == "get_device_types":
        return {
            "ok": True,
            "operation": operation,
            "devices_types": list(devices_types.keys()),
            "devices_instance": {
                key: {
                    "description": value.get("description"),
                    "capability": value.get("capability"),
                    "retrievable": value.get("retrievable", True),
                    "parameters": value.get("parameters"),
                    "default_value": value.get("default_value"),
                }
                for key, value in devices_instance.items()
            },
        }
    if operation == "get_integration_status":
        return {"ok": True, "operation": operation, **_integration_status()}
    raise ValueError(f"Unsupported operation: {operation}")


def mcp_descriptors() -> Tuple[list, list, list]:
    return build_plugin_mcp_descriptors(PLUGIN_NAME, mcp_capabilities())


def mcp_get_prompt(name: str, arguments: dict = None) -> dict:
    arguments = arguments or {}
    notes_block = "\n".join(f"- {note}" for note in _PLUGIN_NOTES)

    if name == _BINDING_PROMPT:
        object_name = str(arguments.get("object_name") or "").strip()
        property_name = str(arguments.get("property_name") or "").strip()
        device_id = arguments.get("device_id")
        instance_name = str(arguments.get("instance") or arguments.get("capability") or "").strip()
        prompt_text = (
            "Bind an osysHome object property to a YandexHome device capability trait.\n"
            f"Plugin: {PLUGIN_NAME}\n"
            f"Object: {object_name or '-'}\n"
            f"Property: {property_name or '-'}\n"
            f"Device id: {device_id or '-'}\n"
            f"Capability instance: {instance_name or '-'}\n\n"
            f"Plugin notes:\n{notes_block}\n\n"
            "Flow:\n"
            "1. invoke get_device_types to pick device type and capability instance\n"
            "2. osys_plugin_entity_schema collection=devices\n"
            "3. Build capability map with linked_object/linked_property (and reportable if push needed)\n"
            "4. osys_plugin_validate_entity then osys_plugin_upsert_entity\n"
            "5. osys_get_property to confirm linked contains YandexHome when reportable=true\n"
            "6. Optional invoke discovery after config/token changes\n"
        )
        return {"messages": [{"role": "user", "content": {"type": "text", "text": prompt_text}}]}

    if name == _ENTITY_AUTHORING_PROMPT:
        task = str(arguments.get("task") or "").strip()
        collection = str(arguments.get("collection") or DEVICES).strip()
        if not task:
            raise ValueError("task is required")
        prompt_text = (
            "Create or update YandexHome plugin entity payload by schema.\n"
            f"Plugin: {PLUGIN_NAME}\nCollection: {collection}\nTask: {task}\n\n"
            f"Plugin notes:\n{notes_block}\n\n"
            "Flow: invoke get_device_types -> osys_plugin_entity_schema -> "
            "validate_entity -> upsert_entity.\n"
            "Output fields: title, type, room, description, manufacturer, model, "
            "sw_version, hw_version, capability.\n"
            "capability example key 'on': "
            "{\"type\":\"on\",\"linked_object\":\"Lamp1\",\"linked_property\":\"status\","
            "\"reportable\":true}.\n"
            "Do not set config; it is generated on save.\n"
        )
        return {"messages": [{"role": "user", "content": {"type": "text", "text": prompt_text}}]}

    raise ValueError(f"Unsupported prompt: {name}")


def mcp_entity_revision(collection: str, entity_id) -> str:
    entity = mcp_get_entity(collection, entity_id)
    if collection == DEVICES:
        return revision_from_dict(
            entity,
            keys=[
                "id",
                "title",
                "type",
                "room",
                "description",
                "manufacturer",
                "model",
                "sw_version",
                "hw_version",
                "capability",
            ],
        )
    raise ValueError(f"Unsupported collection: {collection}")


def _validate_capability_traits(capability: dict) -> List[dict]:
    errors: List[dict] = []
    if not isinstance(capability, dict):
        return [{"field": "capability", "message": "must be an object"}]
    for instance, trait in capability.items():
        if not isinstance(trait, dict):
            errors.append({"field": f"capability.{instance}", "message": "must be an object"})
            continue
        trait_type = trait.get("type") or instance
        if trait_type and trait_type not in devices_instance:
            errors.append({
                "field": f"capability.{instance}.type",
                "message": f"unknown type: {trait_type}",
            })
        linked_object = str(trait.get("linked_object") or "").strip()
        linked_property = str(trait.get("linked_property") or "").strip()
        if linked_object or linked_property:
            if not linked_object or not linked_property:
                errors.append({
                    "field": f"capability.{instance}",
                    "message": "linked_object and linked_property must both be set",
                })
            elif not validate_object_property_exists(linked_object, linked_property):
                errors.append({
                    "field": f"capability.{instance}.linked_property",
                    "message": f"Object property not found: {linked_object}.{linked_property}",
                })
    return errors


def mcp_validate_entity(collection: str, payload: dict, entity_id=None) -> dict:
    if collection != DEVICES:
        raise ValueError(f"Unsupported collection: {collection}")
    if not isinstance(payload, dict):
        return {"ok": False, "errors": [{"field": "_", "message": "payload must be an object"}]}

    merged = _merge_device_payload(payload, entity_id=entity_id)
    schema = mcp_entity_schema(collection)
    result = validate_entity_payload(merged, schema)
    if not result.get("ok"):
        return result

    errors = list(result.get("errors") or [])
    warnings: List[dict] = []

    disallowed = [key for key in payload if key in _DEVICE_READONLY_FIELDS]
    if disallowed:
        return {
            "ok": False,
            "errors": [{"field": disallowed[0], "message": "field is read-only"}],
        }

    device_type = str(merged.get("type") or "").strip()
    if device_type and device_type not in devices_types:
        errors.append({"field": "type", "message": f"unknown device type: {device_type}"})

    if entity_id not in (None, ""):
        with session_scope() as session:
            row = session.query(YaHomeDevice).filter(YaHomeDevice.id == int(entity_id)).one_or_none()
            if row is None:
                errors.append({"field": "id", "message": f"device not found: {entity_id}"})

    title = str(merged.get("title") or "").strip()
    if title and entity_id in (None, ""):
        with session_scope() as session:
            duplicate = _find_device_by_title(session, title)
            if duplicate is not None:
                warnings.append({
                    "field": "title",
                    "message": (
                        f"device title already exists: {title}; "
                        f"upsert without entity_id will update id={duplicate.id}"
                    ),
                })

    if "capability" in payload:
        trait_errors = _validate_capability_traits(_parse_capability(payload.get("capability")))
        errors.extend(trait_errors)
    elif entity_id in (None, "") and not merged.get("capability"):
        warnings.append({
            "field": "capability",
            "message": "device without capability will appear empty in Yandex until traits are added",
        })

    if errors:
        return {"ok": False, "errors": errors, "warnings": warnings}

    response = {"ok": True, "errors": []}
    if warnings:
        response["warnings"] = warnings
    return response
