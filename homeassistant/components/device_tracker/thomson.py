"""
homeassistant.components.device_tracker.thomson
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Device tracker platform that supports scanning a THOMSON router for device
presence.

This device tracker needs telnet to be enabled on the router.

Configuration:

To use the THOMSON tracker you will need to add something like the following
to your config/configuration.yaml

device_tracker:
  platform: thomson
  host: YOUR_ROUTER_IP
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
import re
import threading
import telnetlib

from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from homeassistant.helpers import validate_config
from homeassistant.util import Throttle
from homeassistant.components.device_tracker import DOMAIN

# Return cached results if last scan was less then this time ago
MIN_TIME_BETWEEN_SCANS = timedelta(seconds=10)

_LOGGER = logging.getLogger(__name__)

_DEVICES_REGEX = re.compile(
    r'(?P<mac>(([0-9a-f]{2}[:-]){5}([0-9a-f]{2})))\s' +
    r'(?P<ip>([0-9]{1,3}[\.]){3}[0-9]{1,3})\s+' +
    r'(?P<status>([^\s]+))\s+' +
    r'(?P<type>([^\s]+))\s+' +
    r'(?P<intf>([^\s]+))\s+' +
    r'(?P<hwintf>([^\s]+))\s+' +
    r'(?P<host>([^\s]+))')


# pylint: disable=unused-argument
def get_scanner(hass, config):
    """ Validates config and returns a THOMSON scanner. """
    if not validate_config(config,
                           {DOMAIN: [CONF_HOST, CONF_USERNAME, CONF_PASSWORD]},
                           _LOGGER):
        return None

    scanner = ThomsonDeviceScanner(config[DOMAIN])

    return scanner if scanner.success_init else None


class ThomsonDeviceScanner(object):
    """ This class queries a router running THOMSON firmware
    for connected devices. Adapted from ASUSWRT scanner.
    """

    def __init__(self, config):
        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        self.password = config[CONF_PASSWORD]

        self.lock = threading.Lock()

        self.last_results = {}

        # Test the router is accessible
        data = self.get_thomson_data()
        self.success_init = data is not None

    def scan_devices(self):
        """ Scans for new devices and return a
            list containing found device ids. """

        self._update_info()
        return [client['mac'] for client in self.last_results]

    def get_device_name(self, device):
        """ Returns the name of the given device
            or None if we don't know. """
        if not self.last_results:
            return None
        for client in self.last_results:
            if client['mac'] == device:
                return client['host']
        return None

    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info(self):
        """ Ensures the information from the THOMSON router is up to date.
            Returns boolean if scanning successful. """
        if not self.success_init:
            return False

        with self.lock:
            _LOGGER.info("Checking ARP")
            data = self.get_thomson_data()
            if not data:
                return False

            # flag C stands for CONNECTED
            active_clients = [client for client in data.values() if
                              client['status'].find('C') != -1]
            self.last_results = active_clients
            return True

    def get_thomson_data(self):
        """ Retrieve data from THOMSON and return parsed result.  """
        try:
            telnet = telnetlib.Telnet(self.host)
            telnet.read_until(b'Username : ')
            telnet.write((self.username + '\r\n').encode('ascii'))
            telnet.read_until(b'Password : ')
            telnet.write((self.password + '\r\n').encode('ascii'))
            telnet.read_until(b'=>')
            telnet.write(('hostmgr list\r\n').encode('ascii'))
            devices_result = telnet.read_until(b'=>').split(b'\r\n')
            telnet.write('exit\r\n'.encode('ascii'))
        except EOFError:
            _LOGGER.exception("Unexpected response from router")
            return
        except ConnectionRefusedError:
            _LOGGER.exception("Connection refused by router," +
                              " is telnet enabled?")
            return

        devices = {}
        for device in devices_result:
            match = _DEVICES_REGEX.search(device.decode('utf-8'))
            if match:
                devices[match.group('ip')] = {
                    'ip': match.group('ip'),
                    'mac': match.group('mac').upper(),
                    'host': match.group('host'),
                    'status': match.group('status')
                    }
        return devices
