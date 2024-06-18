devices_types = {
"camera":"Видеокамера, видео-домофон, дверной глазок с камерой",
"cooking":"Холодильник, духовой шкаф",
"cooking.coffee_maker":"Кофеварка, кофемашина",
"cooking.kettle":"Умный чайник, термопот",
"cooking.multicooker":"Мультиварка",
"dishwasher":"Посудомоечная машина",
"humidifier":"Увлажнитель воздуха",
"iron":"Утюг, парогенератор",
"light":"Лампочка, светильник, ночник",
"light.ceiling":"Люстра",
"light.strip":"Диодная лента",
"media_device":"DVD-плеер и другие медиаустройства",
"media_device.receiver":"Спутниковый ресивер, ИК-пульт от ресивера, AV-ресивер",
"media_device.tv":"Умный телевизор, ИК-пульт от телевизора, медиаприставка, ресивер",
"media_device.tv_box":"Умная ТВ-приставка, ИК-пульт от ТВ-приставки",
"openable":"Дверь, ворота, окно, ставни",
"openable.curtain":"Шторы, жалюзи",
"other":"Остальные устройства",
"pet_drinking_fountain":"Поилка",
"pet_feeder":"Кормушка",
"purifier":"Очиститель воздуха, мойка воздуха",
"sensor":"Датчик движения, датчик влажности и другие датчики",
"sensor.button":"Умная кнопка",
"sensor.climate":"Датчик климата",
"sensor.gas":"Датчик газа",
"sensor.illumination":"Датчик освещенности",
"sensor.motion":"Датчик движения",
"sensor.open":"Датчик открытия двери",
"sensor.smoke":"Датчик дыма",
"sensor.vibration":"Датчик вибрации",
"sensor.water_leak":"Датчик протечки воды",
"smart_meter":"Счетчик",
"smart_meter.cold_water":"Счетчик холодной воды",
"smart_meter.electricity":"Счетчик электроэнергии",
"smart_meter.gas":"Счетчик газа",
"smart_meter.heat":"Счетчик тепла",
"smart_meter.hot_water":"Счетчик горячей воды",
"socket":"Умная розетка",
"switch":"Выключатель",
"thermostat":"Водонагреватель, теплый пол, обогреватель, электровентилятор",
"thermostat.ac":"Кондиционер",
"vacuum_cleaner":"Робот-пылесос",
"ventilation.fan":"Вентилятор",
"washing_machine":"Стиральная машина."
}

devices_instance = {
    'controls_locked': {
        'instance_name': 'controls_locked',
        'description': 'Блокировка управления',
        'capability': 'toggle',
        'default_value': False
    },
    'on': {
        'instance_name': 'on',
        'description': 'Включить/выключить',
        'capability': 'on_off',
        'default_value': 0,
        'parameters': {
            'split': False,
        }
    },
    'humidity': {
        'instance_name': 'humidity',
        'description': 'Влажность',
        'capability': 'range',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.percent',
            'range': {
                'min': 0,
                'max': 100,
                'precision': 5
            }
        }
    },
    'volume': {
        'instance_name': 'volume',
        'description': 'Громкость',
        'capability': 'range',
        'default_value': 1,
        'parameters': {
            'range': {
                'min': 1,
                'max': 100,
                'precision': 1
            }
        }
    },
    'input_source': {
        'instance_name': 'input_source',
        'description': 'Источник сигнала',
        'capability': 'mode',
        'default_value': 'one',
        'parameters': {
            'modes': [
                {'value': 'one'},
                {'value': 'two'},
                {'value': 'three'},
                {'value': 'four'},
                {'value': 'five'}
            ],
            'ordered': False
        }
    },
    'pause': {
        'instance_name': 'pause',
        'description': 'Пауза',
        'capability': 'toggle',
        'default_value': False
    },
    'backlight': {
        'instance_name': 'backlight',
        'description': 'Подсветка',
        'capability': 'toggle',
        'default_value': False
    },
    'mute': {
        'instance_name': 'mute',
        'description': 'Режим без звука',
        'capability': 'toggle',
        'default_value': False
    },
    'oscillation': {
        'instance_name': 'oscillation',
        'description': 'Режим вращения',
        'capability': 'toggle',
        'default_value': False
    },
    'ionization': {
        'instance_name': 'ionization',
        'description': 'Режим ионизации',
        'capability': 'toggle',
        'default_value': False
    },
    'keep_warm': {
        'instance_name': 'keep_warm',
        'description': 'Режим поддержания тепла',
        'capability': 'toggle',
        'default_value': False
    },
    'fan_speed': {
        'instance_name': 'fan_speed',
        'description': 'Скорость вентиляции',
        'capability': 'mode',
        'parameters': {
            'modes': [
                {'value': 'auto'},
                {'value': 'low'},
                {'value': 'medium'},
                {'value': 'high'}
            ],
            'ordered': True
        }
    },
    'open': {
        'instance_name': 'open',
        'description': 'Степень открытия',
        'capability': 'range',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.percent',
            'range': {
                'min': 0,
                'max': 100,
                'precision': 10
            }
        }
    },
    'channel': {
        'instance_name': 'channel',
        'description': 'ТВ-канал',
        'capability': 'range',
        'default_value': 1,
        'parameters': {
            'range': {
                'min': 0,
                'max': 999,
                'precision': 1
            }
        }
    },
    'temperature': {
        'instance_name': 'temperature',
        'description': 'Температура',
        'capability': 'range',
        'default_value': 20,
        'parameters': {
            'unit': 'unit.temperature.celsius',
            'range': {
                'min': 1,
                'max': 100,
                'precision': 1
            }
        }
    },
    'thermostat': {
        'instance_name': 'thermostat',
        'description': 'Температурный режим',
        'capability': 'mode',
        'parameters': {
            'modes': [
                {'value': 'auto'},
                {'value': 'heat'},
                {'value': 'cool'},
                {'value': 'eco'},
                {'value': 'dry'},
                {'value': 'fan_only'},
                {'value': 'turbo'},
            ],
            'ordered': True
        }
    },
    'temperature_k': {
        'instance_name': 'temperature_k',
        'description': 'Цветовая температура',
        'capability': 'color_setting',
        'default_value': 4500,
        'parameters': {
            'temperature_k': {
                'min': 2700,
                'max': 9000,
                'precision': 1
            }
        }
    },
    'rgb': {
        'instance_name': 'rgb',
        'description': 'Цвет в формате RGB',
        'capability': 'color_setting',
        'default_value': '000000',
        'parameters': {
            'color_model': 'rgb'
        }
    },
    'brightness': {
        'instance_name': 'brightness',
        'description': 'Яркость',
        'capability': 'range',
        'default_value': 50,
        'parameters': {
            'unit': 'unit.percent',
            'range': {
                'min': 1,
                'max': 100,
                'precision': 1
            }
        }
    },
    'amperage_sensor': {
        'instance_name': 'amperage_sensor',
        'description': 'Сила тока',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.ampere'
        }
    },
    'battery_level_sensor': {
        'instance_name': 'battery_level_sensor',
        'description': 'Уровень заряда',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.percent'
        }
    },
    'co2_level_sensor': {
        'instance_name': 'co2_level_sensor',
        'description': 'Углекислый газ',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.ppm'
        }
    },
    'humidity_sensor': {
        'instance_name': 'humidity_sensor',
        'description': 'Влажность',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.percent'
        }
    },
    'illumination_sensor': {
        'instance_name': 'illumination_sensor',
        'description': 'Освещенность',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.illumination.lux'
        }
    },
    'pm1_density_sensor': {
        'instance_name': 'pm1_density_sensor',
        'description': 'Загрязнение воздуха частицами PM1',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.density.mcg_m3'
        }
    },
    'pm2.5_density_sensor': {
        'instance_name': 'pm2.5_density_sensor',
        'description': 'Загрязнение воздуха частицами PM2.5',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.density.mcg_m3'
        }
    },
    'pm10_density_sensor': {
        'instance_name': 'pm10_density_sensor',
        'description': 'Загрязнение воздуха частицами PM10',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.density.mcg_m3'
        }
    },
    'power_sensor': {
        'instance_name': 'power_sensor',
        'description': 'Мощность',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.watt'
        }
    },
    'electricity_meter_sensor': {
        'instance_name': 'electricity_meter_sensor',
        'description': 'Показания электроэнергии',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.kilowatt_hour'
        }
    },
    'water_meter_sensor': {
        'instance_name': 'water_meter_sensor',
        'description': 'Показания воды',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.cubic_meter'
        }
    },
    'gas_meter_sensor': {
        'instance_name': 'gas_meter_sensor',
        'description': 'Показания газа',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.cubic_meter'
        }
    },
    'heat_meter_sensor': {
        'instance_name': 'heat_meter_sensor',
        'description': 'Показания тепла',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.gigacalorie'
        }
    },
    'pressure_sensor': {
        'instance_name': 'pressure_sensor',
        'description': 'Давление мм. рт. ст.',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.pressure.mmhg'
        }
    },
    'temperature_sensor': {
        'instance_name': 'temperature_sensor',
        'description': 'Температура',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.temperature.celsius'
        }
    },
    'tvoc_sensor': {
        'instance_name': 'tvoc_sensor',
        'description': 'Загрязнение воздуха органическими веществами',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.density.mcg_m3'
        }
    },
    'voltage_sensor': {
        'instance_name': 'voltage_sensor',
        'description': 'Напряжение',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.volt'
        }
    },
    'water_level_sensor': {
        'instance_name': 'water_level_sensor',
        'description': 'Уровень воды',
        'capability': 'float',
        'default_value': 0,
        'parameters': {
            'unit': 'unit.percent'
        }
    },
    'vibration_sensor': {
        'instance_name': 'vibration_sensor',
        'description': 'Датчик вибрации/падения/переворачивания',
        'capability': 'event',
        'default_value': 0,
        'parameters': {
            'events': [
                {'value': 'tilt'},
                {'value': 'fall'},
            ]
        }
    },
    'open_sensor': {
        'instance_name': 'open_sensor',
        'description': 'Датчик открытия/закрытия',
        'capability': 'event',
        'default_value': 0,
        'parameters': {
            'events': [
                {'value': 'opened'},
                {'value': 'closed'},
            ]
        }
    },
    'button_sensor': {
        'instance_name': 'button_sensor',
        'description': 'Событие нажатия кнопки',
        'capability': 'event',
        'default_value': 0,
        'parameters': {
            'events': [
                {'value': 'click'},
                {'value': 'double_click'},
                {'value': 'long_press'},
            ]
        }
    },
    'motion_sensor': {
        'instance_name': 'motion_sensor',
        'description': 'Датчик движения',
        'capability': 'event',
        'default_value': 0,
        'parameters': {
            'events': [
                {'value': 'detected'},
                {'value': 'not_detected'},
            ]
        }
    },
    'smoke_sensor': {
        'instance_name': 'smoke_sensor',
        'description': 'Датчик дыма',
        'capability': 'event',
        'default_value': 0,
        'parameters': {
            'events': [
                {'value': 'detected'},
                {'value': 'not_detected'},
                {'value': 'high'},
            ]
        }
    },
    'gas_sensor': {
        'instance_name': 'gas_sensor',
        'description': 'Датчик наличия газа в помещении',
        'capability': 'event',
        'default_value': 0,
        'parameters': {
            'events': [
                {'value': 'detected'},
                {'value': 'not_detected'},
                {'value': 'high'},
            ]
        }
    },
    'water_leak_sensor': {
        'instance_name': 'water_leak_sensor',
        'description': 'Датчик протечки',
        'capability': 'event',
        'default_value': 0,
        'parameters': {
            'events': [
                {'value': 'dry'},
                {'value': 'leak'},
            ]
        }
    },
}
