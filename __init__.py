r'''
# Модуль YandexHome
Управление умным домом с помощью Алисы от Яндекса.

## Требования
* Доменное имя
* SSL сертификат для работы HTTPS (можно использовать бесплатный от Let's Entrypt)

## Установка
* Идём на https://dialogs.yandex.ru/ и нажимаем "Создать навык" -> "Создать диалог" -> "Умный дом"
* Заполняем название (не принципиально)
* Заполняем Endpoint URL: https://_ваш-домен_/YandexHome
* Не показывать в каталоге -> ставим галочку
* Официальный навык -> нет
* Заполняем остальные поля и загружаем иконку - всё это абсолютно неважно для приватного навыка
* Нажимаем "Авторизация" -> "Cоздать"
* Придумываем, запоминаем и вписываем идентификатор приложения и секрет
* URL авторизации: https://_ваш-домен_/YandexHome/auth/
* URL для получения токена: https://_ваш-домен_/YandexHome/token/
* "Сохранить"->"Cохранить"->"На модерацию" - модерация должна пройти мгновенно в случае приватного навыка
* "Опубликовать"
* Укажите Username, Password, Client ID, Client secret в настройках модуля
* Откройте вкладку "Тестирование" в панели управления Яндекс диалогами и попробуйте связать аккаунты, используя указанные в настройках имя пользователя и пароль
* Проверяйте, должно работать как в панели для тестирования, так и на всех устройствах привязанных к вашему аккаунту
'''

import os
import time
import string
import random
import json
import requests
import urllib
import traceback
from sqlalchemy import or_
from flask import request, render_template, jsonify, redirect, make_response
from app.core.main.BasePlugin import BasePlugin
from app.core.lib.cache import findInCache, saveToCache
from app.core.lib.object import getProperty, setProperty
from app.database import row2dict, session_scope
from plugins.YandexHome.forms.SettingsForm import SettingsForm
from plugins.YandexHome.models.YandexHomeDevices import YaHomeDevice
from plugins.YandexHome.constants import devices_types, devices_instance
from app.authentication.handlers import handle_admin_required
from app.core.lib.object import setLinkToObject, removeLinkFromObject

PREFIX_CAPABILITIES = 'devices.capabilities.'
PREFIX_PROPERTIES = 'devices.properties.'
PREFIX_TYPES = 'devices.types.'

class YandexHome(BasePlugin):

    def __init__(self,app):
        super().__init__(app,__name__)
        self.title = "Yandex Home"
        self.description = """Yandex smart home"""
        self.category = "App"
        self.version = "0.2"
        self.actions = ["search"]

        self.last_code = None
        self.last_code_user = None
        self.last_code_time = None

    def initialization(self):
        pass

    def admin(self, request):
        op = request.args.get("op", None)
        id = request.args.get('device', None)
        if op == 'add' or op == 'edit':
            return render_template("yandexhome_device.html", id=id)

        if op == 'delete':
            id = request.args.get("device", None)
            from sqlalchemy import delete
            with session_scope() as session:
                self.delete_device(int(id))
                sql = delete(YaHomeDevice).where(YaHomeDevice.id == int(id))
                session.execute(sql)
                session.commit()
                return redirect(self.name)

        settings = SettingsForm()
        if request.method == 'GET':
            settings.user_id.data = self.config.get('USER_ID','')
            settings.user_password.data = self.config.get('USER_PASSWORD','')
            settings.client_id.data = self.config.get('CLIENT_ID','')
            settings.client_secret.data = self.config.get("CLIENT_SECRET",'')
            settings.client_key.data = self.config.get("CLIENT_KEY",'')
            settings.skill_id.data = self.config.get("SKILL_ID",'')
        else:
            if settings.validate_on_submit():
                self.config["USER_ID"] = settings.user_id.data
                self.config["USER_PASSWORD"] = settings.user_password.data
                self.config["CLIENT_ID"] = settings.client_id.data
                self.config["CLIENT_SECRET"] = settings.client_secret.data
                self.config["CLIENT_KEY"] = settings.client_key.data
                self.config["SKILL_ID"] = settings.skill_id.data
                self.saveConfig()
        devices = YaHomeDevice.query.all()
        devs = {}
        for dev in devices:
            dev = row2dict(dev)
            dev["caps"] = json.loads(dev['capability'])
            if dev['room'] not in devs.keys():
                devs[dev['room']] = []
            devs[dev['room']].append(dev)
        devs = dict(sorted(devs.items()))
        content = {
            "form": settings,
            "devices": devs,
        }
        return self.render('yandexhome_main.html', content)

    def search(self, query: str) -> str:
        res = []
        devices = YaHomeDevice.query.filter(or_(YaHomeDevice.title.contains(query),YaHomeDevice.description.contains(query),YaHomeDevice.capability.contains(query))).all()
        for device in devices:
            res.append({"url":f'YandexHome?op=edit&device={device.id}', "title":f'{device.title} ({device.description})', "tags":[{"name":"YandexHome","color":"primary"},{"name":"Device","color":"danger"}]})
        return res

    def make_unsorted_response(self, results_dict: dict, status_code: int):
        resp = make_response({}, status_code)
        j_string = json.dumps(results_dict, separators=(',', ':'))
        resp.set_data(value=j_string)
        return resp

    def generateConfig(self, device):
        config = {}
        config["id"] = str(device.id)
        config["name"] = device.title
        config["type"] = PREFIX_TYPES + device.type
        config["room"] = device.room
        config["description"] = device.description
        config["device_info"] = {
            "manufacturer": device.manufacturer,
            "model": device.model,
            "hw_version": device.hw_version,
            "sw_version": device.sw_version
        }
        capabilities = []
        properties = []
        new_dev_traits = json.loads(device.capability)
        if isinstance(new_dev_traits, dict):
            for key, trait in new_dev_traits.items():
                parameters = {}

                # Отправка в Яндекс
                trait['reportable'] = trait['reportable'] if 'reportable' in trait else False

                if trait['reportable']:
                    setLinkToObject(trait['linked_object'], trait['linked_property'], self.name)

                if devices_instance[trait['type']]['capability'] in ['float', 'event']:
                    trait_type = PREFIX_PROPERTIES + devices_instance[trait['type']]['capability']
                else:
                    trait_type = PREFIX_CAPABILITIES + devices_instance[trait['type']]['capability']

                if devices_instance[trait['type']]['capability'] in ['float', 'event']:
                    instance_name = trait['type'].replace('_sensor', '')
                    instance_name = instance_name.replace('_event', '')
                else:
                    instance_name = trait['type']

                if 'parameters' in devices_instance[trait['type']]:
                    parameters = dict(devices_instance[trait['type']]['parameters'])
                    if trait['type'] not in ['rgb', 'temperature_k', 'color_scene']:
                        parameters['instance'] = instance_name
                    if 'range' in parameters:
                        if 'min' in trait:
                            parameters['range']['min'] = float(trait['min'])
                        if 'max' in trait:
                            parameters['range']['max'] = float(trait['max'])
                        if 'precision' in trait:
                            parameters['range']['precision'] = float(trait['precision'])
                    if 'split' in parameters:
                        if 'split' in trait:
                            parameters['split'] = trait['split']
                    if 'modes' in parameters:
                        parameters["modes"] = trait['modes']
                    if 'color_scene' in parameters:
                        parameters["color_scene"] = {}
                        parameters["color_scene"]["scenes"] = trait['scenes']
                else:
                    parameters['instance'] = instance_name

                check = False
                for key, item in enumerate(capabilities):
                    if item['type'] == trait_type:
                        check = key
                        break

                if check is not False and trait_type == PREFIX_CAPABILITIES + 'color_setting':
                    capabilities[check]['parameters'].update(parameters)
                else:
                    retrievable = devices_instance[trait['type']].get('retrievable', True)

                    if devices_instance[trait['type']]['capability'] in ['float', 'event']:
                        properties.append({
                            'type': trait_type,
                            'parameters': parameters,
                            'retrievable': retrievable,
                            'reportable': trait['reportable']
                        })
                    else:
                        capabilities.append({
                            'type': trait_type,
                            'parameters': parameters,
                            'retrievable': retrievable,
                            'reportable': trait['reportable']
                        })

        config["capabilities"] = capabilities
        config["properties"] = properties

        return config

    def changeLinkedProperty(self, obj, prop, value):
        client_key = self.config.get("CLIENT_KEY",'')
        if client_key == '':
            return

        find = False
        with session_scope() as session:
            devices = session.query(YaHomeDevice).filter(YaHomeDevice.capability.contains(obj),YaHomeDevice.capability.contains(prop)).all()
            for device in devices:
                dev = []
                caps = json.loads(device.capability)
                for instance, cap in caps.items():
                    if cap['linked_object'] == obj and cap['linked_property'] == prop:

                        if 'reportable' not in cap or not cap['reportable']:
                            continue  # skip

                        find = True
                        self.logger.debug("send value to yandexhome server %s %s",instance, value)

                        capabilities = []
                        properties = []
                        state = {}

                        # send new value
                        if devices_instance[cap['type']]['capability'] in ['float', 'event']:
                            instance = cap['type'].replace('_sensor', '')
                            instance = instance.replace('_event', '')
                            state['instance'] = instance
                        else:
                            state['instance'] = cap['type']
                            if cap['type'] == "color_scene":
                                state['instance'] = "scene"

                        if cap['type'] in ['on', 'mute', 'pause', 'backlight', 'keep_warm', 'ionization', 'oscillation', 'controls_locked']:
                            state['value'] = bool(value)
                        elif "_sensor" in cap['type']:
                            state['value'] = float(value)
                        elif cap['type'] in ['vibration_event', 'motion_event', 'smoke_event', 'gas_event']:
                            state['value'] = 'detected' if value else 'not_detected'
                        elif cap['type'] == 'water_leak_event':
                            state['value'] = 'leak' if value else 'dry'
                        elif cap['type'] == 'rgb':
                            value = value.lstrip('#')
                            state['value'] = int(value, 16)
                        elif cap['type'] == 'open_event':
                            state['value'] = 'closed' if value == 1 else 'opened'
                        elif cap['type'] in ['open', 'volume', 'channel', 'humidity', 'brightness', 'temperature', 'temperature_k']:
                            state['value'] = int(value)
                        else:
                            state['value'] = value

                        if devices_instance[cap['type']]['capability'] in ['float', 'event']:
                            properties.append({
                                'type': f"{PREFIX_PROPERTIES}{devices_instance[cap['type']]['capability']}",
                                'state': state
                            })
                        else:
                            capabilities.append({
                                'type': f"{PREFIX_CAPABILITIES}{devices_instance[cap['type']]['capability']}",
                                'state': state
                            })

                        dev.append({
                            "id": str(device.id),
                            'capabilities': capabilities,
                            'properties': properties
                        })

                        payload = {
                            "user_id": self.config['USER_ID'],
                            "devices": dev
                        }

                        send = {
                            'ts': int(time.time()),
                            'payload': payload
                        }

                        log_message = f"PropertySetHandle send: {json.dumps(send)}"
                        self.logger.debug(log_message)  # Assuming WriteLog writes to the console or replace with appropriate logging function
                        skill = self.config['SKILL_ID']
                        url = f"https://dialogs.yandex.net/api/v1/skills/{skill}/callback/state"
                        headers = {
                            'Content-type': 'application/json',
                            'Authorization': f"OAuth {client_key}"
                        }

                        response = requests.post(url, headers=headers, json=send)

                        self.logger.debug(f"PropertySetHandle send result: {response.text}")  # Assuming WriteLog writes to the console or replace with appropriate logging function

        if not find:
            removeLinkFromObject(obj,prop,self.name)

    def discovery(self):
        client_key = self.config.get("CLIENT_KEY",'')
        if client_key == '':
            return
        skill = self.config['SKILL_ID']
        url = f"https://dialogs.yandex.net/api/v1/skills/{skill}/callback/discovery"
        headers = {
            'Content-type': 'application/json',
            'Authorization': f"OAuth {client_key}"
        }
        payload = {
            "user_id": self.config['USER_ID'],
        }
        send = {
            'ts': int(time.time()),
            'payload': payload
        }
        response = requests.post(url, headers=headers, json=send)
        self.logger.info(f"Discovery send result: {response.text}")

    def delete_device(self, device_id):
        client_key = self.config.get("CLIENT_KEY",'')
        if client_key == '':
            return
        url = f"https://api.iot.yandex.net/v1.0/devices/{device_id}"
        headers = {
            'Authorization': f"Bearer {client_key}"
        }
        response = requests.delete(url, headers=headers)
        self.logger.info(f"Delete send result: {response.text}")

    def route_index(self):
        @self.blueprint.route('/YandexHome/device', methods=['POST'])
        @self.blueprint.route('/YandexHome/device/<device_id>', methods=['GET', 'POST'])
        @handle_admin_required
        def point_device(device_id=None):
            if request.method == "GET":
                dev = YaHomeDevice.get_by_id(device_id)
                return jsonify(row2dict(dev))
            if request.method == "POST":
                data = request.get_json()
                with session_scope() as session:
                    if data['id']:
                        device = session.query(YaHomeDevice).where(YaHomeDevice.id == int(data['id'])).one()
                    else:
                        device = YaHomeDevice()
                        session.add(device)
                        session.commit()

                    device.title = data['title']
                    device.description = data['description']
                    device.type = data['type']
                    device.room = data['room']
                    device.description = data['description']
                    device.manufacturer = data['manufacturer']
                    device.model = data['model']
                    device.sw_version = data['sw_version']
                    device.hw_version = data['hw_version']
                    device.capability = json.dumps(data['capability'])
                    device.config = json.dumps(self.generateConfig(device))
                    session.commit()

                    self.discovery()

                return 'Device updated successfully', 200

        @self.blueprint.route('/YandexHome/types', methods=['GET'])
        @handle_admin_required
        def get_types():
            types = {}
            types['devices_types'] = devices_types
            types['devices_instance'] = devices_instance
            return self.make_unsorted_response(types, 200)

        # OAuth entry point
        @self.blueprint.route('/YandexHome/auth/', methods=['GET', 'POST'])
        def auth():
            try:
                if request.method == 'GET':
                    # Ask user for login and password
                    return render_template('login.html')
                elif request.method == 'POST':
                    if ("username" not in request.form or
                        "password" not in request.form or
                        "state" not in request.args or
                        "response_type" not in request.args or
                        request.args["response_type"] != "code" or
                        "client_id" not in request.args or
                        request.args["client_id"] != self.config["CLIENT_ID"]): # noqa
                            self.logger.error("Invalid auth request") # noqa
                            return "Invalid request", 400
                    # Check login and password
                    user = self.get_user(request.form["username"])
                    if user is None or user["password"] != request.form["password"]:
                        self.logger.warning("invalid password")
                        return render_template('login.html', login_failed=True)

                    # Generate random code and remember this user and time
                    self.last_code = self.random_string(8)
                    self.last_code_user = request.form["username"]
                    self.last_code_time = time.time()

                    params = {
                        'state': request.args['state'], 
                        'code': self.last_code,
                        'client_id': self.config["CLIENT_ID"]
                    }
                    self.logger.info("code generated")
                    return redirect(request.args["redirect_uri"] + '?' + urllib.parse.urlencode(params))
            except Exception as ex:
                self.logger.error(traceback.format_exc())
                return f"Error {type(ex).__name__}: {str(ex)}", 500

        # OAuth, token request
        @self.blueprint.route('/YandexHome/token/', methods=['POST'])
        def token():
            try:
                request.user_id = self.last_code_user
                if ("client_secret" not in request.form
                    or request.form["client_secret"] != self.config["CLIENT_SECRET"]
                    or "client_id" not in request.form
                    or request.form["client_id"] != self.config["CLIENT_ID"]
                    or "code" not in request.form): # noqa
                        self.logger.error("Invalid token request") # noqa
                        return "Invalid request", 400
                # Check code
                if request.form["code"] != self.last_code:
                    self.logger.warning("invalid code")
                    return "Invalid code", 403
                # Check time
                if time.time() - self.last_code_time > 10:
                    self.logger.warning("code is too old")
                    return "Code is too old", 403
                # Generate and save random token with username
                access_token = self.random_string(32)
                saveToCache(access_token,self.last_code_user.encode('utf-8'),self.name)
                self.logger.info("access granted")
                # Return just token without any expiration time
                return jsonify({'access_token': access_token})
            except Exception as ex:
                self.logger.error(traceback.format_exc())
                return f"Error {type(ex).__name__}: {str(ex)}", 500

        # Just placeholder for root
        @self.blueprint.route('/YandexHome/')
        def root():
            return "Your smart home is ready."

        # Script must response 200 OK on this request
        @self.blueprint.route('/YandexHome/v1.0', methods=['GET', 'POST'])
        def main_v10():
            return "OK"

        # Method to revoke token
        @self.blueprint.route('/YandexHome/v1.0/user/unlink', methods=['POST'])
        def unlink():
            try:
                user_id = self.check_token()
                if user_id is None:
                    return "Access denied", 403
                access_token = self.get_token()
                request_id = request.headers.get('X-Request-Id')
                access_token_file = findInCache(access_token, self.name)
                if os.path.isfile(access_token_file) and os.access(access_token_file, os.R_OK):
                    os.remove(access_token_file)
                    self.logger.info(f"token {access_token} revoked", access_token)
                return jsonify({'request_id': request_id})
            except Exception as ex:
                self.logger.error(traceback.format_exc())
                return f"Error {type(ex).__name__}: {str(ex)}", 500

        # Devices list
        @self.blueprint.route('/YandexHome/v1.0/user/devices', methods=['GET'])
        def devices_list():
            try:
                user_id = self.check_token()
                if user_id is None:
                    return "Access denied", 403
                request_id = request.headers.get('X-Request-Id')
                self.logger.debug(f"devices request #{request_id}")
                devices = []
                devs = YaHomeDevice.query.all()
                for dev in devs:
                    device = json.loads(dev.config)
                    devices.append(device)
                result = {'request_id': request_id, 'payload': {'user_id': user_id, 'devices': devices}}
                self.logger.debug(f"devices response #{request_id}: \r\n{json.dumps(result, indent=4)}")
                return jsonify(result)
            except Exception as ex:
                self.logger.error(traceback.format_exc())
                return f"Error {type(ex).__name__}: {str(ex)}", 500

        # Method to query current device status
        @self.blueprint.route('/YandexHome/v1.0/user/devices/query', methods=['POST'])
        def query():
            try:
                user_id = self.check_token()
                if user_id is None:
                    return "Access denied", 403
                request_id = request.headers.get('X-Request-Id')
                r = request.get_json()
                self.logger.debug(f"query request #{request_id}: \r\n{json.dumps(r, indent=4)}")
                devices_request = r["devices"]
                result = {'request_id': request_id, 'payload': {'devices': []}}
                # For each requested device...
                for device in devices_request:
                    new_device = {'id': device['id'], 'capabilities': [], 'properties': []}
                    # Load device config
                    dev = YaHomeDevice.get_by_id(device['id'])
                    if dev is None:
                        self.delete_device(device['id'])
                        return jsonify(result)
                    capabilities = json.loads(dev.capability)
                    # Call it for every requested capability
                    for instance, capability in capabilities.items():
                        # But skip it if it's not retrievable
                        if not capability.get("retrievable", True):
                            continue

                        linked_object = capability['linked_object']
                        linked_property = capability['linked_property']
                        value = getProperty(linked_object + "." + linked_property)

                        # todo convert value
                        if instance in ['on','mute','pause','backlight','keep_warm','ionization','oscillation','controls_locked']:
                            value = value == 1 or value == '1'
                        elif "_sensor" in instance:
                            value = float(value)
                        elif instance in ['vibration_event','motion_event','smoke_event','gas_event']:
                            value = 'detected' if value == 1 else 'not_detected'
                        elif instance == 'water_leak_event':
                            value = 'leak' if value == 1 else 'dry'
                        elif instance == 'rgb':
                            value = value.lstrip('#')
                            value = int(value, 16)
                        elif instance == 'open_event':
                            value = 'closed' if value == 1 else 'opened'
                        elif instance in ['temperature','temperature_k']:
                            value = float(value)
                        elif instance in ['open','volume','channel','humidity','brightness']:
                            value = int(value)
                        elif "_event" in instance:
                            value = str(value)
                        
                        if capability['type'] in devices_instance:
                            if devices_instance[capability['type']]['capability'] in ['float', 'event']:
                                instance = instance.replace('_sensor', '')
                                instance = instance.replace('_event', '')
                                new_device['properties'].append({
                                    'type': PREFIX_PROPERTIES + devices_instance[capability['type']]['capability'],
                                    'state': {
                                        "instance": instance,
                                        "value": value
                                    }
                                })
                            else:
                                if instance == "color_scene":
                                    instance = "scene"

                                new_device['capabilities'].append({
                                    'type': PREFIX_CAPABILITIES + devices_instance[capability['type']]['capability'],
                                    'state': {
                                        "instance": instance,
                                        "value": value
                                    }
                                })

                    result['payload']['devices'].append(new_device)
                self.logger.debug(f"query response #{request_id}: \r\n{json.dumps(result, indent=4)}")
                return jsonify(result)
            except Exception as ex:
                self.logger.error(traceback.format_exc())
                return f"Error {type(ex).__name__}: {str(ex)}", 500

        # Method to execute some action with devices
        @self.blueprint.route('/YandexHome/v1.0/user/devices/action', methods=['POST'])
        def action():
            try:
                user_id = self.check_token()
                if user_id is None:
                    return "Access denied", 403
                request_id = request.headers.get('X-Request-Id')
                user = self.get_user(user_id)
                if user is None:
                    return "Access denied", 403
                r = request.get_json()
                self.logger.debug(f"action request #{request_id}: \r\n{json.dumps(r, indent=4)}")
                devices_request = r["payload"]["devices"]
                result = {'request_id': request_id, 'payload': {'devices': []}}
                # For each requested device...
                for device in devices_request:
                    # Check that user can access this device
                    dev = YaHomeDevice.get_by_id(device["id"])
                    if not dev:
                        return "Access denied", 403
                    new_device = {'id': device['id'], 'capabilities': []}
                    # Call it for every requested capability
                    for capability in device['capabilities']:
                        # Pass parameters: capability type, instance, new value and relative parameter (if any)
                        capability_type = capability['type']
                        state = capability['state']
                        instance = state.get("instance", None)
                        value = state.get("value", None)
                        relative = state.get("relative", False)
                        try:
                            capabilities = json.loads(dev.capability)
                            if instance == "scene":
                                cap = capabilities['color_scene']
                            else:
                                cap = capabilities[instance]
                            
                            linked_object = cap['linked_object']
                            linked_property = cap['linked_property']

                            if relative:
                                cur_val = getProperty(linked_object + "." + linked_property)
                                value = cur_val + value
                            # todo convert value
                            if instance in ['on','mute','pause','backlight','keep_warm','ionization','oscillation','controls_locked']:
                                value = 1 if value else 0
                            elif instance in ['motion_event','smoke_event','gas_event']:
                                value = 1 if value == 'detected' else 0
                            elif instance == 'water_leak_event':
                                value = 1 if value == 'leak' else 0
                            elif instance == 'open_event':
                                value = 1 if value == 'opened' else 0
                            elif instance == 'rgb':
                                value = hex(value)[2:]

                            setProperty(linked_object + "." + linked_property, value, self.name)

                            new_device['capabilities'].append({
                                'type': capability_type,
                                'state': {
                                    "instance": instance,
                                    "action_result": {
                                        "status": "DONE"
                                    }
                                }
                            })
                        except Exception as ex:
                            self.logger.error(traceback.format_exc())
                            new_device['capabilities'].append({
                                'type': capability_type,
                                'state': {
                                    "instance": instance,
                                    "action_result": {
                                        "status": "ERROR",
                                        "error_code": "INTERNAL_ERROR",
                                        "error_message": f"{type(ex).__name__}: {str(ex)}"
                                    }
                                }
                            })
                    result['payload']['devices'].append(new_device)
                self.logger.debug(f"action response #{request_id}: \r\n{json.dumps(result, indent=4)}")
                return jsonify(result)
            except Exception as ex:
                self.logger.error(traceback.format_exc())
                return f"Error {type(ex).__name__}: {str(ex)}", 500

    # Function to load user info
    def get_user(self, user_id):
        request.user_id = user_id
        if self.config["USER_ID"] == user_id:
            user = {
                "password": self.config["USER_PASSWORD"]
            }
            return user
        else:
            self.logger.warning(f'User {user_id} not found')
            return None

    # Function to retrieve token from header
    def get_token(self):
        auth = request.headers.get('Authorization')
        parts = auth.split(' ', 2)
        if len(parts) == 2 and parts[0].lower() == 'bearer':
            return parts[1]
        else:
            self.logger.warning(f"Invalid token: {auth}")
            return None

    # Function to check current token, returns username
    def check_token(self):
        access_token = self.get_token()
        access_token_file = findInCache(access_token, self.name)
        if os.path.isfile(access_token_file) and os.access(access_token_file, os.R_OK):
            with open(access_token_file, mode='r') as f:
                user_id = f.read()
                request.user_id = user_id
                return user_id
        else:
            return None

    # Random string generator
    def random_string(self, stringLength=8):
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for i in range(stringLength))
