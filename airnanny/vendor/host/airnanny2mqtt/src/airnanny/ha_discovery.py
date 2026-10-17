"""Structured HA MQTT discovery, shared topic definitions; no HA connection."""
from .config_loader import DaemonConfig
from .mqtt_schema import Topics


def discovery(config: DaemonConfig) -> dict[str, dict]:
    result, unique = {}, set()
    for registered in config.devices:
        device_id = registered.core.name
        topics = Topics(config.mqtt.topic_prefix,device_id)
        device = dict(identifiers=[f'airnanny_{device_id}'],name=registered.friendly_name,
                      manufacturer='AirNanny',model='A7')
        entities = [
            ('switch','power',dict(command='power',value_template='{{ value_json.power }}',
                payload_on='ON',payload_off='OFF',state_on='on',state_off='off')),
            ('select','fan',dict(command='fan',value_template='{{ value_json.fan | string }}',options=list('1234567'))),
            ('select','mode',dict(command='mode',value_template='{{ value_json.mode }}',options=['intake','mixed','recirc'])),
            ('number','temperature',dict(command='temperature',value_template='{{ value_json.temperature }}',
                min=10,max=30,step=0.5,mode='box',unit_of_measurement='°C')),
            ('button','temperature_off',dict(command='temperature',payload_press='off')),
            ('sensor','temperature_control',dict(value_template='{{ value_json.temperature_control }}')),
            ('switch','night',dict(command='night',value_template='{{ value_json.night }}',
                payload_on='ON',payload_off='OFF',state_on='on',state_off='off')),
            ('select','humidifier',dict(command='humidifier',
                value_template="{{ 'off' if value_json.humidifier == 0 else value_json.humidifier | string }}",
                options=['off','1','2'])),
        ]
        for field in ('status_fresh','rx_revision','baseline_generation','baseline_source'):
            entities.append(('sensor',field,dict(value_template='{{ value_json.'+field+' }}',
                entity_category='diagnostic',state_topic=topics.diagnostics)))
        for component, name, fields in entities:
            payload = dict(name=name.replace('_',' ').title(), unique_id=f'airnanny_{device_id}_{name}',
                device=device.copy(), state_topic=topics.state,
                availability=[{'topic':config.mqtt.topic_prefix+'/daemon/availability'}, {'topic':topics.availability}],
                availability_mode='all',payload_available='online',payload_not_available='offline')
            fields = fields.copy()
            command = fields.pop('command',None)
            payload.update(fields)
            if command:
                payload.update(command_topic=topics.command(command),retain=False,optimistic=False)
            if component=='button':
                payload.pop('state_topic');payload.pop('optimistic')
            uid=payload['unique_id']
            if uid in unique: raise ValueError('duplicate HA unique id')
            unique.add(uid)
            result[f'{config.mqtt.discovery_prefix}/{component}/{uid}/config']=payload
    return result
