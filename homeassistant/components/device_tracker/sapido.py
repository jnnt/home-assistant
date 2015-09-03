"""
homeassistant.components.device_tracker.sapido
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Device tracker platform that supports scanning a sapido router for device
presence.

Configuration:

To use the Sapido tracker you will need to add something like the following
to your config/configuration.yaml

device_tracker:
  platform: sapido
  host: YOUR_ROUTER_IP   "http://192.168.1.1/goform/formLogin"
  username: YOUR_ADMIN_USERNAME
  password: YOUR_ADMIN_PASSWORD

Variables:

host
*Required
The IP address of your router, e.g. 192.168.1.1.

username
*Required
The username of an user with administrative privileges, usually 'admin'.

password
*Required
The password for your given admin account.
"""
import logging
from datetime import timedelta
import threading
import requests
import sys
import re

from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from homeassistant.util import Throttle
from homeassistant.components.device_tracker import DOMAIN

# Return cached results if last scan was less then this time ago
MIN_TIME_BETWEEN_SCANS = timedelta(seconds=10)
REQUIREMENTS=['requests']

_LOGGER = logging.getLogger(__name__)


def get_scanner(hass, config):
    """ Validates config and returns a Netgear scanner. """
    info = config[DOMAIN]
    host = info.get(CONF_HOST)
    username = info.get(CONF_USERNAME)
    password = info.get(CONF_PASSWORD)

    if password is not None and host is None:
        _LOGGER.warning('Found username or password but no host')
        return None
    scanner = SapidoDeviceScanner(host, username, password)

    return scanner


class SapidoDeviceScanner(object):
    """ This class queries a Sapido wireless router using the SOAP-API. """

    RE_MAC = r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})"

    def __init__(self, host, username, password):
        self.host = "http://"+host
        self.username = username
        self.password = password


    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _get_devices(self):
        s = requests.session()
        res = s.post(
            self.host + "/goform/formLogin",
            data={'username': self.username, 'password': self.password}
        )
        _LOGGER.info('Sapido login result: %s', res.status_code)
        try:
            res = s.get(self.host + "/wlstatbl.asp")
            mac_addresses = re.findall(self.RE_MAC, str(res.content))
            _LOGGER.info('Got devices: %s', mac_addresses,)
        except:
            _LOGGER.error('Failed to get devices %s', sys.exc_info())
            mac_addresses = []
        finally:
            s.post(self.host + "/goform/formLogout", data={'logout': 'Apply Change'})
            _LOGGER.info('Sent log out request')
        return mac_addresses



    def scan_devices(self):
        """ Scans for new devices and return a
            list containing found device ids. """
        return self._get_devices()

    def get_device_name(self, mac):
        """ Returns the name of the given device or None if we don't know. """
        return None
