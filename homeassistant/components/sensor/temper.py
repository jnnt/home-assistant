"""
homeassistant.components.sensor.temper
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Support for getting temperature from TEMPer devices.

Configuration:
To use the temper sensors you will need to add something like the following to
your config/configuration.yaml

Example:

sensor:
    platform: temper
"""
import logging
from homeassistant.helpers.entity import Entity
from homeassistant.const import CONF_NAME, DEVICE_DEFAULT_NAME

_LOGGER = logging.getLogger(__name__)

REQUIREMENTS = ['https://github.com/rkabadi/temper-python/archive/' +
                '3dbdaf2d87b8db9a3cd6e5585fc704537dd2d09b.zip']


# pylint: disable=unused-argument
def setup_platform(hass, config, add_devices_callback, discovery_info=None):
    """ Find and return Temper sensors. """
    try:
        # pylint: disable=no-name-in-module, import-error
        from temperusb.temper import TemperHandler
    except ImportError:
        _LOGGER.error('Failed to import temperusb')
        return False

    temp_unit = hass.config.temperature_unit
    name = config.get(CONF_NAME, DEVICE_DEFAULT_NAME)
    temper_devices = TemperHandler().get_devices()
    add_devices_callback([TemperSensor(dev, temp_unit, name + '_' + str(idx))
                          for idx, dev in enumerate(temper_devices)])


class TemperSensor(Entity):
    """ Represents an Temper temperature sensor. """
    def __init__(self, temper_device, temp_unit, name):
        self.temper_device = temper_device
        self.temp_unit = temp_unit
        self.current_value = None
        self._name = name

    @property
    def name(self):
        """ Returns the name of the temperature sensor. """
        return self._name

    @property
    def state(self):
        """ Returns the state of the entity. """
        return self.current_value

    @property
    def unit_of_measurement(self):
        """ Unit of measurement of this entity, if any. """
        return self.temp_unit

    def update(self):
        """ Retrieve latest state. """
        try:
            self.current_value = self.temper_device.get_temperature()
        except IOError:
            _LOGGER.error('Failed to get temperature due to insufficient '
                          'permissions. Try running with "sudo"')
