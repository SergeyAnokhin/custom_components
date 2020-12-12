"""
Tracking for bluetooth low energy devices.

"""
import asyncio
import logging

import voluptuous as vol
from homeassistant.helpers.event import track_point_in_utc_time
from homeassistant.components.device_tracker.legacy import (
    YAML_DEVICES,
    async_load_config,
)
from homeassistant.components.device_tracker.const import (
    CONF_TRACK_NEW,
    CONF_SCAN_INTERVAL,
    SCAN_INTERVAL,
    SOURCE_TYPE_BLUETOOTH_LE,
)
from homeassistant.components.device_tracker import PLATFORM_SCHEMA
import homeassistant.util.dt as dt_util
import homeassistant.helpers.config_validation as cv
import struct
import bluetooth._bluetooth as bluez
import time

_LOGGER = logging.getLogger(__name__)

REQUIREMENTS = ['PyBluez==0.22']

BLE_PREFIX = 'BLE_'
MIN_SEEN_NEW = 5
CONF_SCAN_DURATION = 'scan_duration'
CONF_BLUETOOTH_DEVICE = 'device_id'

OGF_LE_CTL = 0x08
OCF_LE_SET_SCAN_ENABLE = 0x000C
LE_META_EVENT = 0x3e
EVT_LE_CONN_COMPLETE = 0x01
EVT_LE_ADVERTISING_REPORT = 0x02
COMPLETE_LOCAL_NAME = 0x09
SHORTENED_LOCAL_NAME = 0x08

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_SCAN_DURATION, default=10): cv.positive_int,
    vol.Optional(CONF_BLUETOOTH_DEVICE, default='0'): cv.string
})


def setup_scanner(hass, config, see, discovery_info=None):
    def packed_bdaddr_to_string(bdaddr_packed):
        return ':'.join('%02x' % i for i in struct.unpack("<BBBBBB", bdaddr_packed[::-1]))

    def returnnumberpacket(pkt):
        myInteger = 0
        multiple = 256
        for c in pkt:
            myInteger += int(c) * multiple
            multiple = 1
        return myInteger

    def returnstringpacket(pkt):
        myString = ""
        for c in pkt:
            myString += "%02x" % (c,)
        return myString

    """Set up the Bluetooth LE Scanner."""
    new_devices = {}

    def see_device(address, name, new_device=False):
        """Mark a device as seen."""
        if new_device:
            if address in new_devices:
                _LOGGER.debug(
                    "Seen %s %s times", address, new_devices[address])
                new_devices[address] += 1
                if new_devices[address] >= MIN_SEEN_NEW:
                    _LOGGER.debug("Adding %s to tracked devices", address)
                    devs_to_track.append(address)
                else:
                    return
            else:
                _LOGGER.debug("Seen %s for the first time", address)
                new_devices[address] = 1
                return

        see(mac=BLE_PREFIX + address, host_name=name.strip("\x00"),
            source_type=SOURCE_TYPE_BLUETOOTH_LE)

    duration = config.get(CONF_SCAN_DURATION)
    hciId = int(config.get(CONF_BLUETOOTH_DEVICE)[3:])
    sock = bluez.hci_open_dev(hciId)
    _LOGGER.debug('Connected to bluetooth adapter hci%i', hciId)

    cmd_pkt = struct.pack("<BB", 0x01, 0x00)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)
    _LOGGER.debug('Activated BLE scan on bluetooth adapter hci%i', hciId)

    def discover_ble_devices():
        """Discover Bluetooth LE devices."""
        _LOGGER.debug("Discovering Bluetooth LE devices")
        try:
            #[{'name': None, 'address': 'A4:77:33:C2:D0:5F'}, {'name': 'BF PPG Project', 'address': 'A0:E6:F8:75:50:84'}]
            devices = {}

            startTime = time.time()
            while time.time() < startTime + duration:

                old_filter = sock.getsockopt(
                    bluez.SOL_HCI, bluez.HCI_FILTER, 14)
                flt = bluez.hci_filter_new()
                bluez.hci_filter_all_events(flt)
                bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
                sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, flt)

                pkt = sock.recv(255)
                ptype, event, plen = struct.unpack("BBB", pkt[:3])

                if event == LE_META_EVENT:
                    subevent, = struct.unpack("B", pkt[3:4])
                    pkt = pkt[4:]
                    if subevent == EVT_LE_ADVERTISING_REPORT:
                        num_reports = struct.unpack("B", pkt[0:1])[0]
                        report_pkt_offset = 0
                        report_event_type = struct.unpack(
                            "B", pkt[report_pkt_offset + 1: report_pkt_offset + 1 + 1])[0]

                        for i in range(0, num_reports):
                            macAdressSeen = packed_bdaddr_to_string(pkt[3:9])
                            rssi, = struct.unpack(
                                "b", pkt[report_pkt_offset-1:])

                            #Look for 0x09 - "Complete Local Name" or 0x08 - "Shortened Local Name"
                            #Read AD type and length after mac address
                            report_pkt_offset = report_pkt_offset + 10
                            len, adType = struct.unpack(
                                "BB", pkt[report_pkt_offset: report_pkt_offset + 2])
                            name = ""

                            while(adType != COMPLETE_LOCAL_NAME and adType != SHORTENED_LOCAL_NAME and report_pkt_offset + len + 2 < plen - 1):
                                report_pkt_offset = report_pkt_offset + len + 1
                                len, adType = struct.unpack(
                                    "BB", pkt[report_pkt_offset: report_pkt_offset + 2])

                            if adType == COMPLETE_LOCAL_NAME:
                                name = pkt[report_pkt_offset +
                                           2: report_pkt_offset + len + 1].decode('UTF-8')
                            elif adType == SHORTENED_LOCAL_NAME:
                                name = pkt[report_pkt_offset +
                                           2: report_pkt_offset + len + 1].decode('UTF-8')

                            devices[macAdressSeen.upper()] = name
                sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, old_filter)

            _LOGGER.debug("Bluetooth LE devices discovered = %s", devices)
        except RuntimeError as error:
            _LOGGER.error("Error during Bluetooth LE scan: %s", error)
            devices = []
        return devices

    yaml_path = hass.config.path(YAML_DEVICES)
    devs_to_track = []
    devs_donot_track = []

    # Load all known devices.
    # We just need the devices so set consider_home and home range
    # to 0
    for device in asyncio.run_coroutine_threadsafe(
        async_load_config(yaml_path, hass, 0), hass.loop
    ).result():
        # check if device is a valid bluetooth device
        if device.mac and device.mac[:4].upper() == BLE_PREFIX:
            if device.track:
                _LOGGER.debug("Adding %s to BLE tracker", device.mac)
                devs_to_track.append(device.mac[4:])
            else:
                _LOGGER.debug("Adding %s to BLE do not track", device.mac)
                devs_donot_track.append(device.mac[4:])

    # if track new devices is true discover new devices
    # on every scan.
    track_new = config.get(CONF_TRACK_NEW)

    if not devs_to_track and not track_new:
        _LOGGER.warning("No Bluetooth LE devices to track!")
        return False

    interval = config.get(CONF_SCAN_INTERVAL, SCAN_INTERVAL)

    def update_ble(now):
        """Lookup Bluetooth LE devices and update status."""
        devs = discover_ble_devices()
        for mac in devs_to_track:
            _LOGGER.debug("Checking %s", mac)
            result = mac in devs
            _LOGGER.debug("Checking %s", result)

            if not result:
                # Could not lookup device name
                continue
            if devs[mac] is None:
                devs[mac] = mac
            see_device(mac, devs[mac])

        if track_new:
            for address in devs:
                if address not in devs_to_track and \
                        address not in devs_donot_track:
                    _LOGGER.info("Discovered Bluetooth LE device %s", address)
                    see_device(address, devs[address], new_device=True)

        track_point_in_utc_time(hass, update_ble, dt_util.utcnow() + interval)

    update_ble(dt_util.utcnow())

    return True
