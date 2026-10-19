"""Cards Home Assistant can draw, over the topics the daemon already owns.

The reviewed discovery publishes a switch, two selects, a number and a
button per A7. Every control is there, but Home Assistant lays them out as
eight unrelated tiles, and a breather is not eight things -- it is one
appliance with a target temperature, a fan speed and an air source.

Two entities describe it as what it is. A `fan` entity is the ventilation:
on, a speed, and where the air comes from. A `climate` entity is the heater:
a target temperature on a dial. Home Assistant draws each as its own card.

Both are added, never substituted: their own unique ids on the same device,
so the reviewed entities are neither replaced nor renamed, and they drive
the same command topics with the same payloads the reviewed parser already
accepts. Nothing new is subscribed and no new command path exists -- which
is the point, because the reviewed path is the one that confirms a command
against the device before reporting it.

The two overlap on power, because the appliance has one switch and both
cards have to be able to reach it. Fan speed and air source appear on both
for the same reason: either card should be usable on its own.

State stays non-optimistic. Every attribute is read from the retained state
document the daemon publishes from confirmed device state, and `optimistic`
is off, so the card moves when the unit says so and not when someone
presses something.

One honest limit. Home Assistant sends an HVAC mode to a single topic, and
turning temperature control off is a different command on a different topic
from powering the unit on. So the modes offered are `off` and `heat`, which
each do exactly one thing that the unit then confirms; `fan_only` would have
had to either silently not work or guess at a second command. Temperature
control is still turned off by the reviewed Temperature Off button, and when
it is off the unit reports no target and the dial shows none.

There is no ambient reading here because the protocol work to decode one is
not done. The card shows a target without a current temperature, which is
what Home Assistant does for a thermostat that reports no sensor.
"""
from .mqtt_schema import Topics

# What Home Assistant understands, mapped to what the unit reports. The
# literal "None" is Home Assistant's own payload for "this attribute is not
# known", so a unit that has not yet confirmed a value clears the control
# instead of leaving a stale one on display.
NONE = 'None'

FAN_SPEED_MIN = 1
FAN_SPEED_MAX = 7
FAN_MODES = [str(speed) for speed in range(FAN_SPEED_MIN, FAN_SPEED_MAX + 1)]
PRESET_MODES = ['intake', 'mixed', 'recirc']
MODES = ['off', 'heat']

MIN_TEMP = 10
MAX_TEMP = 30
TEMP_STEP = 0.5


def _shared(config, registered):
    """The parts both entities state identically, so they cannot drift."""
    device_id = registered.core.name
    topics = Topics(config.mqtt.topic_prefix, device_id)
    return topics, {
        'device': {'identifiers': ['airnanny_%s' % device_id],
                   'name': registered.friendly_name,
                   'manufacturer': 'AirNanny', 'model': 'A7'},
        # Exactly the reviewed entities' availability, so a card cannot
        # claim to know something while they say the unit is gone.
        'availability': [{'topic': config.mqtt.topic_prefix + '/daemon/availability'},
                         {'topic': topics.availability}],
        'availability_mode': 'all',
        'payload_available': 'online',
        'payload_not_available': 'offline',
        'optimistic': False,
        'retain': False,
    }


def climate(config):
    """A climate discovery message per configured device."""
    result, seen = {}, set()
    for registered in config.devices:
        topics, shared = _shared(config, registered)
        unique_id = 'airnanny_%s_climate' % registered.core.name
        if unique_id in seen:
            raise ValueError('duplicate HA unique id')
        seen.add(unique_id)
        payload = dict(shared)
        payload.update({
            'name': None,  # the device's own name, so the card is not "X X"
            'unique_id': unique_id,

            'modes': list(MODES),
            'mode_command_topic': topics.command('power'),
            # Any mode that is not off powers the unit on. Rendering 'off'
            # for an unknown power state as well keeps the template inside
            # the offered modes; the entity is unavailable at that point
            # anyway, so nothing is displayed from it.
            'mode_command_template': "{{ 'off' if value == 'off' else 'on' }}",
            'mode_state_topic': topics.state,
            'mode_state_template': "{{ 'heat' if value_json.power == 'on' else 'off' }}",

            'temperature_command_topic': topics.command('temperature'),
            'temperature_state_topic': topics.state,
            'temperature_state_template':
                "{%% if value_json.temperature is none %%}%s"
                "{%% else %%}{{ value_json.temperature }}{%% endif %%}" % NONE,
            'temperature_unit': 'C',
            'min_temp': MIN_TEMP,
            'max_temp': MAX_TEMP,
            'temp_step': TEMP_STEP,
            'precision': TEMP_STEP,

            'fan_modes': list(FAN_MODES),
            'fan_mode_command_topic': topics.command('fan'),
            'fan_mode_state_topic': topics.state,
            'fan_mode_state_template':
                "{%% if value_json.fan is none %%}%s"
                "{%% else %%}{{ value_json.fan }}{%% endif %%}" % NONE,

            'preset_modes': list(PRESET_MODES),
            'preset_mode_command_topic': topics.command('mode'),
            'preset_mode_state_topic': topics.state,
            'preset_mode_value_template':
                "{%% if value_json.mode is none %%}%s"
                "{%% else %%}{{ value_json.mode }}{%% endif %%}" % NONE,
        })
        result['%s/climate/%s/config' % (config.mqtt.discovery_prefix, unique_id)] = payload
    return result


def fan(config):
    """A fan discovery message per configured device.

    The unit is a ventilator first: this is the card that says so. Speed is
    a percentage over the seven steps the unit actually has, which reads
    better than a list of seven numbers, and Home Assistant converts in both
    directions from the range declared here.
    """
    result, seen = {}, set()
    for registered in config.devices:
        topics, shared = _shared(config, registered)
        unique_id = 'airnanny_%s_fan_unit' % registered.core.name
        if unique_id in seen:
            raise ValueError('duplicate HA unique id')
        seen.add(unique_id)
        payload = dict(shared)
        payload.update({
            'name': None,
            'unique_id': unique_id,

            'command_topic': topics.command('power'),
            'payload_on': 'on',
            'payload_off': 'off',
            'state_topic': topics.state,
            'state_value_template':
                "{%% if value_json.power is none %%}%s"
                "{%% else %%}{{ value_json.power }}{%% endif %%}" % NONE,

            # Declared as a range rather than a list of percentages: Home
            # Assistant then publishes one of the seven steps the unit
            # understands, instead of an arbitrary percentage it would have
            # to round somewhere else.
            'percentage_command_topic': topics.command('fan'),
            'percentage_state_topic': topics.state,
            'percentage_value_template':
                "{%% if value_json.fan is none %%}%s"
                "{%% else %%}{{ value_json.fan }}{%% endif %%}" % NONE,
            'speed_range_min': FAN_SPEED_MIN,
            'speed_range_max': FAN_SPEED_MAX,

            'preset_mode_command_topic': topics.command('mode'),
            'preset_mode_state_topic': topics.state,
            'preset_mode_value_template':
                "{%% if value_json.mode is none %%}%s"
                "{%% else %%}{{ value_json.mode }}{%% endif %%}" % NONE,
            'preset_modes': list(PRESET_MODES),
        })
        result['%s/fan/%s/config' % (config.mqtt.discovery_prefix, unique_id)] = payload
    return result


def entities(config):
    """Every card this adds, in one mapping."""
    messages = {}
    for part in (fan(config), climate(config)):
        overlap = set(messages) & set(part)
        if overlap:
            raise ValueError('duplicate discovery topic: ' + ', '.join(sorted(overlap)))
        messages.update(part)
    return messages
