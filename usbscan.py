import json
import logging
import subprocess
import psutil
import win32api
import win32com
import win32com.client
import win32file
import pythoncom


try:
    # requires administrative priviledges
    agent_com = win32com.client.Dispatch("SentinelHelper.1").GetAgentStatusJSON()
    agent_info = json.loads(agent_com)
    sentinelctl = (
        "C:\\Program Files\\SentinelOne\\Sentinel Agent %s\\SentinelCtl.exe"
        % agent_info["agent-version"]
    )

except:
    # doesn't require admin
    sentinelui: list = []
    for p in psutil.process_iter(["name", "pid"]):
        if p.info["name"] == "SentinelUI.exe":
            sentinelui.append(psutil.Process(p.info["pid"]).exe())
    sentinelctl = sentinelui[0].replace("SentinelUI.exe", "SentinelCtl.exe")


class AgentEvents:
    """Recieve events from SentinelAgent.1"""

    def OnQuit(self):
        """
        SentinelAgent has quit. This would impair the reporting of malicious scan findings, if not
        break the ability to scan using SentinelCtl.exe.
        """
        logging.info("usb_scan: Sentinel agent quit!")

    def OnDeviceControlEvent(self, event):
        """
        Sample Device Control event data for a connected removable media device.
        {
            "deviceClass": 8,
            "deviceName": "SanDisk Cruzer Blade",
            "eventId": "{96e5a854-abb7-11ec-ba75-000c29ad0249}",
            "eventType": "connected",
            "interface": "USB",
            "productId": 21863,
            "ruleId": "-1",
            "serialId": "4C530110050104113372",
            "timestamp": "2022-03-24T21:19:00.894+00:00",
            "vendorId": 1921
        }
        """
        device_event = json.loads(event)

        if (
            device_event["eventType"] == "connected"
            and device_event["deviceClass"] == 8
        ):
            logging.info("usb_scan: Found USB device %s", device_event["deviceName"])
            drives = win32api.GetLogicalDriveStrings().split("\x00")[:-1]
            for device in drives:
                drive_type = win32file.GetDriveType(device)
                if drive_type == win32file.DRIVE_REMOVABLE:
                    # Found removable device
                    is_scan = subprocess.run(
                        [sentinelctl, "is_scan_in_progress"],
                        stdout=subprocess.PIPE,
                        check=True,
                    ).stdout.decode("utf-8")
                    # Previous scan still running
                    if is_scan.startswith("Scan is in progress"):
                        logging.info("usb_scan: A scan is already in progress...")
                        abort_scan = subprocess.run(
                            [sentinelctl, "abort_scan"],
                            stdout=subprocess.PIPE,
                            check=True,
                        ).stdout.decode("utf-8")
                        logging.info("usb_scan: %s", abort_scan)
                    scan_status = subprocess.run(
                        [sentinelctl, "scan_folder", "-i", device],
                        stdout=subprocess.PIPE,
                        check=True,
                    ).stdout.decode("utf-8")
                    logging.info("usb_scan: %s", scan_status)


if __name__ == "__main__":
    logging.basicConfig(
        filename="usb_scan.log",
        filemode="a",
        format="%(asctime)s %(message)s",
        level=logging.DEBUG,
    )
    agent = win32com.client.DispatchWithEvents("SentinelAgent.1", AgentEvents)
    pythoncom.PumpMessages()

