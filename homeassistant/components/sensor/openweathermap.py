"""
homeassistant.components.sensor.openweathermap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
OpenWeatherMap (OWM) service.

Configuration:

To use the OpenWeatherMap sensor you will need to add something like the
following to your config/configuration.yaml

sensor:
  platform: openweathermap
  api_key: YOUR_APP_KEY
  forecast: 0 or 1
  monitored_conditions:
    - weather
    - temperature
    - wind_speed
    - humidity
    - pressure
    - clouds
    - rain
    - snow

Variables:

api_key
*Required
To retrieve this value log into your account at http://openweathermap.org/

forecast
*Optional
Enables the forecast. The default is to display the current conditions.

monitored_conditions
*Optional
Conditions to monitor. See the configuration example above for a
list of all available conditions to monitor.

Details for the API : http://bugs.openweathermap.org/projects/api/wiki

Only metric measurements are supported at the moment.
"""
import logging
from datetime import timedelta

from homeassistant.util import Throttle
from homeassistant.const import (CONF_API_KEY, TEMP_CELCIUS, TEMP_FAHRENHEIT)
from homeassistant.helpers.entity import Entity

REQUIREMENTS = ['pyowm==2.2.1']
_LOGGER = logging.getLogger(__name__)
SENSOR_TYPES = {
    'weather': ['Condition', ''],
    'temperature': ['Temperature', ''],
    'wind_speed': ['Wind speed', 'm/s'],
    'humidity': ['Humidity', '%'],
    'pressure': ['Pressure', 'hPa'],
    'clouds': ['Cloud coverage', '%'],
    'rain': ['Rain', 'mm'],
    'snow': ['Snow', 'mm']
}

# Return cached results if last scan was less then this time ago
MIN_TIME_BETWEEN_UPDATES = timedelta(seconds=120)


def setup_platform(hass, config, add_devices, discovery_info=None):
    """ Get the OpenWeatherMap sensor. """

    if None in (hass.config.latitude, hass.config.longitude):
        _LOGGER.error("Latitude or longitude not set in Home Assistant config")
        return False

    try:
        from pyowm import OWM

    except ImportError:
        _LOGGER.exception(
            "Unable to import pyowm. "
            "Did you maybe not install the 'PyOWM' package?")

        return False

    SENSOR_TYPES['temperature'][1] = hass.config.temperature_unit
    unit = hass.config.temperature_unit
    forecast = config.get('forecast', 0)
    owm = OWM(config.get(CONF_API_KEY, None))

    if not owm:
        _LOGGER.error(
            "Connection error "
            "Please check your settings for OpenWeatherMap.")
        return None

    data = WeatherData(owm, forecast, hass.config.latitude,
                       hass.config.longitude)
    dev = []
    try:
        for variable in config['monitored_conditions']:
            if variable not in SENSOR_TYPES:
                _LOGGER.error('Sensor type: "%s" does not exist', variable)
            else:
                dev.append(OpenWeatherMapSensor(data, variable, unit))
    except KeyError:
        pass

    if forecast == 1:
        SENSOR_TYPES['forecast'] = ['Forecast', '']
        dev.append(OpenWeatherMapSensor(data, 'forecast', unit))

    add_devices(dev)


# pylint: disable=too-few-public-methods
class OpenWeatherMapSensor(Entity):
    """ Implements an OpenWeatherMap sensor. """

    def __init__(self, weather_data, sensor_type, temp_unit):
        self.client_name = 'Weather'
        self._name = SENSOR_TYPES[sensor_type][0]
        self.owa_client = weather_data
        self.temp_unit = temp_unit
        self.type = sensor_type
        self._state = None
        self._unit_of_measurement = SENSOR_TYPES[sensor_type][1]
        self.update()

    @property
    def name(self):
        return '{} {}'.format(self.client_name, self._name)

    @property
    def state(self):
        """ Returns the state of the device. """
        return self._state

    @property
    def unit_of_measurement(self):
        """ Unit of measurement of this entity, if any. """
        return self._unit_of_measurement

    # pylint: disable=too-many-branches
    def update(self):
        """ Gets the latest data from OWM and updates the states. """

        self.owa_client.update()
        data = self.owa_client.data
        fc_data = self.owa_client.fc_data

        if self.type == 'weather':
            self._state = data.get_detailed_status()
        elif self.type == 'temperature':
            if self.temp_unit == TEMP_CELCIUS:
                self._state = round(data.get_temperature('celsius')['temp'],
                                    1)
            elif self.temp_unit == TEMP_FAHRENHEIT:
                self._state = round(data.get_temperature('fahrenheit')['temp'],
                                    1)
            else:
                self._state = round(data.get_temperature()['temp'], 1)
        elif self.type == 'wind_speed':
            self._state = data.get_wind()['speed']
        elif self.type == 'humidity':
            self._state = data.get_humidity()
        elif self.type == 'pressure':
            self._state = round(data.get_pressure()['press'], 0)
        elif self.type == 'clouds':
            self._state = data.get_clouds()
        elif self.type == 'rain':
            if data.get_rain():
                self._state = round(data.get_rain()['3h'], 0)
                self._unit_of_measurement = 'mm'
            else:
                self._state = 'not raining'
                self._unit_of_measurement = ''
        elif self.type == 'snow':
            if data.get_snow():
                self._state = round(data.get_snow(), 0)
                self._unit_of_measurement = 'mm'
            else:
                self._state = 'not snowing'
                self._unit_of_measurement = ''
        elif self.type == 'forecast':
            self._state = fc_data.get_weathers()[0].get_status()


class WeatherData(object):
    """ Gets the latest data from OpenWeatherMap. """

    def __init__(self, owm, forecast, latitude, longitude):
        self.owm = owm
        self.forecast = forecast
        self.latitude = latitude
        self.longitude = longitude
        self.data = None
        self.fc_data = None

    @Throttle(MIN_TIME_BETWEEN_UPDATES)
    def update(self):
        """ Gets the latest data from OpenWeatherMap. """
        obs = self.owm.weather_at_coords(self.latitude, self.longitude)
        self.data = obs.get_weather()

        if self.forecast == 1:
            obs = self.owm.three_hours_forecast_at_coords(self.latitude,
                                                          self.longitude)
            self.fc_data = obs.get_forecast()
