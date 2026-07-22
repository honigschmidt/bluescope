import asyncio
from collections import deque
import csv
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import pathlib
import re
import time
from typing import Any

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.exc import BleakError, BleakDeviceNotFoundError, BleakBluetoothNotAvailableError
from dacite import from_dict
from platformdirs import user_state_path
import readchar
from rich.console import Console
from rich.live import Live
from rich.logging import RichHandler
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

APP_NAME = "BlueScope"
console = Console()

@dataclass
class ScanManagerEntry:
    device_address: str
    device_name: str | None = None
    device_local_name: str | None = None
    device_manufacturer_id: int | None = None
    device_manufacturer_name: str | None = None
    device_first_seen_utc: str | None = None
    device_last_seen_utc: str | None = None

    @property
    def display_name(self) -> str:
        return self.device_local_name or self.device_name or "N/A" 
    
    @property
    def display_manufacturer(self) -> str:
        return self.device_manufacturer_name or "N/A"
    
    @property
    def summary_string(self) -> str:
        return f"{self.device_address} | {self.display_name} | {self.display_manufacturer}"

@dataclass
class MonitoringManagerEntry:
    device_address: str
    device_name: str | None = None
    device_manufacturer_name: str | None = None
    device_rssi_history: deque[float] = field(default_factory=lambda: deque(maxlen=5))
    device_tx_power: int | None = None
    device_last_seen_utc: datetime | None = None

@dataclass
class DiscoveryManagerMetadata:
    device_name: str | None = None
    device_discover_time_utc: str | None = None

@dataclass
class DiscoveryManagerCharacteristic:
    service_uuid: str | None = None
    service_description: str | None = None
    char_uuid: str | None = None
    char_properties: list | None = None
    char_read_hex: str | None = None
    char_read_utf8: str | None = None
    char_discover_time_utc: str | None = None

@dataclass
class DiscoveryManagerEntry:
    metadata: DiscoveryManagerMetadata
    characteristics: list[DiscoveryManagerCharacteristic] = field(default_factory=list)

class InteractionManager:
    SCAN_TIME_MIN_SEC = 5
    SCAN_TIME_MAX_SEC = 3600
    BT_ADDRESS_VALIDATION_PATTERN = re.compile(
        r"^("
        r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
        r"|"
        r"([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}"
        r"|"
        r"[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}"
        r")$"
    )
    LOGGER_NAME = "bluescope.interaction"

    def __init__(self):
        self.message_map = {
            "scan": f"Enter scan timeout ({self.SCAN_TIME_MIN_SEC}-{self.SCAN_TIME_MAX_SEC} seconds) or press [ENTER] to exit: ",
            "discovery": "Enter device address to discover or press [ENTER] to exit: ",
            "monitoring": "Enter device address to monitor or press [ENTER] to exit: ",
        }
        self.validator_map = {
            "scan": self.validate_scan_input,
            "discovery": self.validate_discovery_input,
            "monitoring": self.validate_monitoring_input,
        }
        self.logger = logging.getLogger(self.LOGGER_NAME)

    async def read_user_input(self, input_type: str) -> str | None:
        is_input_valid = False
        user_input = ""
        while not is_input_valid:
            prompt = self.message_map.get(input_type)
            user_input = await asyncio.to_thread(input, prompt)
            user_input = user_input.strip()
            validator = self.validator_map.get(input_type)
            is_input_valid = validator(user_input)
        if not user_input:
            return None
        return user_input
    
    def validate_scan_input(self, user_input: str) -> bool:
        if user_input.isdigit():
            user_input = int(user_input)
            if (user_input >= self.SCAN_TIME_MIN_SEC and user_input <= self.SCAN_TIME_MAX_SEC):
                return True
        if user_input == "":
            return True
        else:
            self.logger.warning("Timeout value must be a number between %s and %s seconds", self.SCAN_TIME_MIN_SEC, self.SCAN_TIME_MAX_SEC)
            return False
    
    def validate_discovery_input(self, user_input: str) -> bool:
        if self.check_regex_pattern(user_input):
            return True
        else:
            self.logger.warning("Invalid MAC address to discover: '%s'", user_input)
            return False
    
    def validate_monitoring_input(self, user_input:str) -> bool:
        if self.check_regex_pattern(user_input):
            return True
        else:
            self.logger.warning("Invalid MAC address to monitor: '%s'", user_input)
            return False
    
    def check_regex_pattern(self, user_input: str) -> bool:
        return bool (self.BT_ADDRESS_VALIDATION_PATTERN.match(user_input)) or user_input == ""

class StorageManager:
    LOG_DIR = f"{APP_NAME.lower()}_log_dir"
    CID_DIR = "cid"
    CID_FILE = "cid.csv"
    LOGGER_NAME = "bluescope.storage"

    def __init__(self):
        self.last_save_day = datetime.now(timezone.utc).strftime("%Y_%m_%d")
        self.log_dir_path = self.get_log_dir_path()
        self.logger = logging.getLogger(self.LOGGER_NAME)
        self.write_queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue()
        self.worker_task: asyncio.Task | None = None

    def start_queue_worker(self) -> None:
        if self.worker_task is None or self.worker_task.done():
            self.worker_task = asyncio.create_task(self.queue_worker())
    
    async def shutdown_queue_worker(self) -> None:
        if self.worker_task and not self.worker_task.done():
            await self.write_queue.put(None)
            await self.write_queue.join()
    
    async def queue_worker(self) -> None:
        while True:
            try:
                queue_item = await self.write_queue.get()
                if queue_item is None:
                    self.write_queue.task_done()
                    break
                log_type, data = queue_item
                await self.save_log_async(log_type, data)
                self.write_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Write queue error: %s", e)
                self.write_queue.task_done()

    def get_log_dir_path(self) -> pathlib.Path:
        state_path = user_state_path(appname=APP_NAME.lower(), appauthor=False)

        try:
            state_path.mkdir(parents=True, exist_ok=True)
            return state_path
        except (OSError, PermissionError) as e:
            self.logger.warning("Failed to create log directory '%s': %s. Trying fallback...", state_path, e)

        try:
            file_path = pathlib.Path(__file__).resolve()
            base_path = file_path.parent
            fallback_path = base_path / self.LOG_DIR
            fallback_path.mkdir(parents=True, exist_ok=True)
            return fallback_path
        except OSError as e:
            self.logger.error("Critical failure: Could not create any writable log directory: %s.", e)
            raise
        
    async def load_log_async(self, log_type: str) -> dict:
        type_map = {
            "scan": ScanManagerEntry,
            "discovery": DiscoveryManagerEntry
        }
        data_class = type_map.get(log_type)
        file_name = f"{log_type}_log_{datetime.now(timezone.utc).strftime('%Y_%m_%d')}.json"
        file_path = os.path.join(self.log_dir_path, file_name)

        def read_and_parse_sync() -> dict:
            data = {}
            try:
                with open(file_path, mode="r", encoding="utf-8") as f:
                    json_data = json.load(f)
                    for device_address, device_data in json_data.items():
                        data[device_address] = from_dict(data_class=data_class, data=device_data)
                self.logger.info("Log file loaded successfully: '%s'", file_name)
            except FileNotFoundError:
                self.logger.info("No historical log found. Log file '%s' initialized.", file_name)
            except Exception as e:
                self.logger.error("Failed to parse log file '%s': %s", file_name, e)
            return data
        return await asyncio.to_thread(read_and_parse_sync)

    async def save_log_async(self, log_type: str, data: dict) -> None:
        if not data:
            return None
        await asyncio.to_thread(self.serialize_and_write_sync, log_type, data)
        
    def serialize_and_write_sync(self, log_type: str, data: dict) -> None:
        if not data:
            return
        current_day = datetime.now(timezone.utc).strftime("%Y_%m_%d")
        if current_day == self.last_save_day:
            file_name = f"{log_type}_log_{current_day}.json"
        else:
            file_name = f"{log_type}_log_{self.last_save_day}.json"
        file_path = os.path.join(self.log_dir_path, file_name)
        json_data = {}
        for device_address, device_data in data.items():
            if isinstance(device_data, dict):
                json_data[device_address] = device_data
            else:
                json_data[device_address] = asdict(device_data)
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=4)
            self.last_save_day = current_day
            self.logger.info("Log file '%s' written successfully", file_name)
        except Exception as e:
            self.logger.error("Failed to write log file '%s': %s", file_name, e)

    def background_save(self, log_type: str, data: dict[str, ScanManagerEntry]) -> None:
        json_data = {addr: asdict(entry) for addr, entry in data.items()}
        try:
            current_loop = asyncio.get_running_loop()
            self.start_queue_worker()
            current_loop.call_soon_threadsafe(self.write_queue.put_nowait, (log_type, json_data))
        except RuntimeError:
            try:
                self.serialize_and_write_sync(log_type=log_type, data=json_data)
            except Exception as e:
                self.logger.error("Failed to execute background save: %s", e)

    def get_cid_dir_path(self) -> pathlib.Path | None:
        file_path = pathlib.Path(__file__).resolve()
        base_path = file_path.parent
        cid_dir_path = base_path / self.CID_DIR
        if not cid_dir_path.is_dir():
            return None
        return cid_dir_path

    def load_cid_registry(self) -> dict:
        cid_dir_path = self.get_cid_dir_path()
        if not cid_dir_path:
            return None
        cid_file = os.path.join(cid_dir_path, self.CID_FILE)
        try:
            with open(cid_file, mode="r", encoding="utf-8") as f:
                reader = csv.reader(f)
                return {rows[0].strip().upper(): rows[1].strip() for rows in reader}
        except (FileNotFoundError, PermissionError, UnicodeDecodeError) as e:
            self.logger.error("Failed to load CID registry: %s", e)
            return {}

class ManufacturerRegistry:
    def __init__(self, storage_manager: StorageManager):
        self.storage_manager = storage_manager
        self.cid_cache = {
            "0x0006": "Microsoft",
            "0x000D": "Texas Instruments",
            "0x000F": "Broadcom",
            "0x004C": "Apple, Inc.",
            "0x0059": "Nordic Semiconductor",
            "0x0075": "Samsung Electronics",
            "0x00E0": "Google",
            "0x0211": "Intel Corporation",
            "0x02D0": "Amazon.com Services LLC",
            "0x052B": "Xiaomi Inc."
        }
        self.cid_registry = storage_manager.load_cid_registry()
    
    def resolve_cid(self, manufacturer_id: int | None) -> str | None:
        if manufacturer_id is None:
            return None
        cid_hex = f"0x{manufacturer_id:04X}"
        if cid_hex in self.cid_cache:
            return self.cid_cache.get(cid_hex)
        return self.cid_registry.get(cid_hex, str(manufacturer_id))

class ScanManager:
        SAVE_INTERVAL_SEC = 5
        LOGGER_NAME = "bluescope.scan"

        def __init__(
            self,
            storage_manager: StorageManager,
            manufacturer_registry: ManufacturerRegistry
        ):
            self.storage_manager = storage_manager
            self.manufacturer_registry = manufacturer_registry
            self.discovered_devices: dict[str, ScanManagerEntry] = {}
            self.new_device_count = 0
            self.known_device_count = 0
            self.save_interval = self.SAVE_INTERVAL_SEC
            self.last_save = time.time()
            self.logger = logging.getLogger(self.LOGGER_NAME)
        
        def _on_detection(self, device: BLEDevice, advertisement_data: AdvertisementData) -> None:
            current_day = datetime.now(timezone.utc).strftime("%Y_%m_%d")

            if current_day != self.storage_manager.last_save_day:
                self.storage_manager.background_save(log_type="scan", data=self.discovered_devices)
                self.discovered_devices.clear()
                self.storage_manager.last_save_day = current_day
                self.new_device_count = 0

            addr = device.address
            utc_now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            is_new = addr not in self.discovered_devices

            if is_new:
                self.new_device_count += 1
                mfr_id = next(iter(advertisement_data.manufacturer_data), None)
                mfr_name = self.manufacturer_registry.resolve_cid(mfr_id)
                entry = ScanManagerEntry(
                    device_address=addr,
                    device_name=device.name,
                    device_local_name=advertisement_data.local_name,
                    device_manufacturer_id=mfr_id,
                    device_manufacturer_name=mfr_name,
                    device_first_seen_utc=utc_now,
                    device_last_seen_utc=utc_now,
                )
                self.discovered_devices[addr] = entry
                console.print(f"[bold magenta][+] {entry.summary_string}[/bold magenta]")
            else:
                self.known_device_count += 1
                entry = self.discovered_devices[addr]
                entry.device_last_seen_utc = utc_now
                console.print(f"[*] {entry.summary_string}")

            if time.time() - self.last_save > self.save_interval:
                self.storage_manager.background_save(log_type="scan", data=self.discovered_devices)
                self.last_save = time.time()

        async def scan(self, scan_timeout:int) -> None:
            scanner = BleakScanner(scanning_mode="active", detection_callback=self._on_detection)
            self.discovered_devices = await self.storage_manager.load_log_async(log_type="scan")
            scan_start = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            self.logger.info("Scan started. Press [CTRL+C] to terminate.")
            try:
                async with scanner:
                    await asyncio.sleep(scan_timeout)
                    self.logger.info("Scan completed")
            except (KeyboardInterrupt, asyncio.CancelledError):
                self.logger.info("Scan terminated")
            finally:
                summary_text = (
                   "--------------------------------------\n"
                    f"SCAN SUMMARY - {scan_start}\n"
                    "--------------------------------------\n"
                    f"[+] NEW DEVICES DETECTED :{self.new_device_count:>12}\n"
                    f"[*] KNOWN DEVICES SEEN   :{self.known_device_count:>12}\n"
                    f"[=] TOTAL SEEN           :{self.new_device_count + self.known_device_count:>12}\n"
                    "--------------------------------------"
                )
                console.print(summary_text, highlight=False)
                await self.storage_manager.save_log_async(log_type="scan", data=self.discovered_devices)

class DiscoveryManager:
    DEVICE_NAME_UUID = "00002a00-0000-1000-8000-00805f9b34fb"
    DISCOVER_TIMEOUT_SEC = 10
    LOGGER_NAME = "bluescope.discovery"

    def __init__(self, storage_manager: StorageManager):
        self.storage_manager = storage_manager
        self.device_characteristics: dict[str, DiscoveryManagerEntry] = {}
        self.logger = logging.getLogger(self.LOGGER_NAME)
        
    def _on_disconnect(self, client: BleakClient) -> None:
        self.logger.info("Connection to device '%s' closed", client.address)

    async def discover(self, device_address: str) -> None:
        client = BleakClient(
            address_or_ble_device=device_address,
            disconnected_callback=self._on_disconnect,
            timeout=self.DISCOVER_TIMEOUT_SEC,
        )
        self.device_characteristics = await self.storage_manager.load_log_async(log_type="discovery")
        self.logger.info("Connecting to device '%s'...", device_address)

        try:
            async with client:
                self.logger.info("Connected to device '%s'", device_address)
                try:
                    device_name = await client.read_gatt_char(self.DEVICE_NAME_UUID)
                    device_name_utf = device_name.decode("utf-8").strip("\x00 \t\n\r")
                except Exception:
                    device_name_utf = None
                self.device_characteristics[device_address] = DiscoveryManagerEntry(
                    metadata = DiscoveryManagerMetadata(
                        device_name=device_name_utf,
                        device_discover_time_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    )
                )
                device_tree = Tree(f"[bold cyan]Device:[/bold cyan] {device_name_utf} [{device_address}]")
                for service in client.services:
                    service_node = device_tree.add(f"[bold yellow]Service:[/bold yellow] {service.uuid} ({service.description})")
                    for char in service.characteristics:
                        char_node = service_node.add(f"[green]Char:[/green] {char.uuid} -> {char.properties}")
                        char_read_hex = None
                        char_read_utf8 = None
                        if "read" in char.properties:
                            try:
                                char_read_raw = await client.read_gatt_char(char.uuid)
                                if char_read_raw is not None:
                                    char_node.add(f"[blue]RAW[/blue]: [dim cyan]{char_read_raw}[/dim cyan]")
                                    char_read_hex = char_read_raw.hex().upper()
                                    char_node.add(f"[magenta]HEX:[/magenta] [bold magenta]{char_read_hex}[/bold magenta]")
                                    char_read_utf8 = char_read_raw.decode("utf-8", errors="ignore").rstrip("\x00")
                                    char_node.add(f"[orange3]UTF-8:[/orange3] [white]{char_read_utf8}[/white]")
                            except Exception as e:
                                char_node.add(f"[bold red]Read Error:[/bold red] [red]Unable to read ({type(e).__name__})[/red]")

                        characteristic = DiscoveryManagerCharacteristic(
                            service_uuid=service.uuid,
                            service_description=service.description,
                            char_uuid=char.uuid,
                            char_properties=char.properties,
                            char_read_hex=char_read_hex,
                            char_read_utf8=char_read_utf8,
                            char_discover_time_utc=datetime.now(timezone.utc).isoformat(),
                        )
                        self.device_characteristics[device_address].characteristics.append(characteristic)
                console.print(device_tree, end="\n")
                await self.storage_manager.save_log_async(log_type="discovery", data=self.device_characteristics)

        except BleakDeviceNotFoundError:
            self.logger.error("Target device '%s' is out of range or powered off", device_address)
        except BleakBluetoothNotAvailableError as e:
            self.logger.error("Your system's Bluetooth is turned off or blocked. Reason: %s", e.reason)
        except asyncio.TimeoutError:
            self.logger.error("Connection attempt to device '%s' timed out", device_address)
        except BleakError as e:
            self.logger.error("Bleak failed to initialize connection: %s", e)
        except Exception as e:
            self.logger.error("Unexpected system error occurred: %s", e)

class MonitoringManager:
    RSSI_AVG_WINDOW = 5
    RSSI_AVG_IMM_DB = -45
    RSSI_AVG_NEAR_DB = -70
    RSSI_AVG_FAR_DB = -90
    STALE_TIME_SEC = 10
    PRIVACY_MASK_ENABLED = False
    MON_DATA_REFRESH_RATE_SEC = 0.25
    MON_TABLE_REFRESH_FREQ = 4
    ADDR_LEN_WIN = 17
    ADDR_LEN_MAC = 36
    LOGGER_NAME = "bluescope.monitoring"

    def __init__(self, manufacturer_registry: ManufacturerRegistry):
        self.manufacturer_registry = manufacturer_registry
        self.device_address = None
        self.monitoring_list: dict[str, ScanManagerEntry] = {}
        self.is_auto_mode = True
        self.logger = logging.getLogger(self.LOGGER_NAME)
    
    def _on_detection(self, device: BLEDevice, advertisement_data: AdvertisementData) -> None:
        if not self.is_auto_mode and self.device_address.upper() != device.address.upper():
            return
        entry = self.monitoring_list.get(device.address)
        if not entry:
            entry = MonitoringManagerEntry(
                device_address=device.address,
                device_manufacturer_name = self.manufacturer_registry.resolve_cid(next(iter(advertisement_data.manufacturer_data), None)),
                device_rssi_history=deque(maxlen=self.RSSI_AVG_WINDOW),
            )
            self.monitoring_list[device.address] = entry
        entry.device_name = device.name
        entry.device_rssi_history.append(advertisement_data.rssi)
        entry.device_tx_power = advertisement_data.tx_power
        entry.device_last_seen_utc = datetime.now(timezone.utc)
    
    def build_monitoring_table(self) -> Table:
        table = Table()
        table.add_column("Device Address", justify="center")
        table.add_column("Name", justify="center")
        table.add_column("Mfr", justify="center")
        table.add_column("RSSI", justify="center")
        table.add_column("TX", justify="center")
        table.add_column("Dist", justify="center")
        table.add_column("Last Seen UTC", justify="center")

        for device_entry in self.monitoring_list.values():
            if len(device_entry.device_rssi_history) == self.RSSI_AVG_WINDOW:
                rssi_avg = sum(device_entry.device_rssi_history) / self.RSSI_AVG_WINDOW
                if rssi_avg >= self.RSSI_AVG_IMM_DB:
                    rssi_color = "bold green"
                    device_distance = "Immediate"
                elif rssi_avg >= self.RSSI_AVG_NEAR_DB:
                    rssi_color = "bold yellow"
                    device_distance = "Near"
                elif rssi_avg >= self.RSSI_AVG_FAR_DB:
                    rssi_color = "bold red"
                    device_distance = "Far"
                else:
                    rssi_color = None
                    device_distance = None
            else:
                rssi_avg = 0
                rssi_color = None
                device_distance = None

            entry = [
                self.apply_privacy_mask(device_entry.device_address) if self.PRIVACY_MASK_ENABLED else device_entry.device_address,
                device_entry.device_name if device_entry.device_name else "N/A",
                device_entry.device_manufacturer_name if device_entry.device_manufacturer_name else "N/A",
                Text(f"{rssi_avg}", style=rssi_color) if rssi_avg != 0 else "N/A",
                str(device_entry.device_tx_power) if (device_entry.device_tx_power and device_entry.device_tx_power != 127)  else "N/A",
                device_distance if device_distance else "N/A",
                device_entry.device_last_seen_utc.strftime("%Y-%m-%d %H:%M:%S") if device_entry.device_last_seen_utc else "Searching...",
            ]
            table.add_row(*entry)
        return table
    
    def apply_privacy_mask(self, address: str) -> str:
        if ":" in address:
            return "XX:XX:XX:XX:XX:XX" 
        if "-" in address and len(address) == self.ADDR_LEN_WIN:
            return "XX-XX-XX-XX-XX-XX"
        if len(address) == self.ADDR_LEN_MAC:
            return "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        else:
            return "XX:XX:XX:XX:XX:XX"

    def cleanup_stale_devices(self) -> None:
        now = datetime.now(timezone.utc)
        stale_devices = []
        for device_address, device_entry  in self.monitoring_list.items():
            if device_entry.device_last_seen_utc:
                elapsed_time = (now - device_entry.device_last_seen_utc).total_seconds()
                if elapsed_time > self.STALE_TIME_SEC:
                    stale_devices.append(device_address)
        for device_address in stale_devices:
            del self.monitoring_list[device_address]

    async def monitor(self, device_address: str | None = None) -> None:
        self.monitoring_list.clear()
        self.is_auto_mode = True
        if device_address:
            self.is_auto_mode = False
            self.device_address = device_address.upper()
            entry = MonitoringManagerEntry(
                device_address=device_address,
                device_rssi_history=deque(maxlen=self.RSSI_AVG_WINDOW),
            )
            self.monitoring_list[device_address] = entry
        scanner = BleakScanner(scanning_mode="active", detection_callback=self._on_detection)
        try:
            async with scanner:
                mask_state = "Privacy mask is ON. " if self.PRIVACY_MASK_ENABLED else ""
                self.logger.info("Monitoring started. %sPress [CTRL+C] to terminate.", mask_state)
                with Live(Table(), refresh_per_second=self.MON_TABLE_REFRESH_FREQ) as live:
                    while True:
                        if self.is_auto_mode:
                            self.cleanup_stale_devices()
                        monitoring_table = self.build_monitoring_table()
                        live.update(monitoring_table)
                        await asyncio.sleep(self.MON_DATA_REFRESH_RATE_SEC)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            self.logger.info("Monitoring terminated")

class BlueScopeApp:
    LOG_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S UTC"
    LOGGER_NAME = "bluescope"

    def __init__(self):
        self.is_running = True
        self.init_logging()
        self.console = Console()
        self.interaction_manager = InteractionManager()
        self.storage_manager = StorageManager()
        self.manufacturer_registry = ManufacturerRegistry(storage_manager=self.storage_manager)
        self.scan_manager = ScanManager(storage_manager=self.storage_manager, manufacturer_registry=self.manufacturer_registry)
        self.discovery_manager = DiscoveryManager(storage_manager=self.storage_manager)
        self.monitoring_manager = MonitoringManager(manufacturer_registry=self.manufacturer_registry)

    def init_logging(self) -> None:

        def utc_datetime_formatter(_datetime: datetime) -> str:
            return _datetime.astimezone(timezone.utc).strftime(self.LOG_DATETIME_FORMAT)
            
        formatter = logging.Formatter("%(message)s")
        formatter.converter = time.gmtime
        rich_handler = RichHandler(
            show_time=True,
            log_time_format=utc_datetime_formatter,
            omit_repeated_times=False,
            show_path=False
        )
        rich_handler.setFormatter(formatter)
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        root_logger.addHandler(rich_handler)
        self.logger = logging.getLogger(self.LOGGER_NAME)

    async def run(self) -> None:
        while self.is_running:
            await self.display_menu()

    async def display_menu(self) -> None:
        menu_text = (
            f"\n{APP_NAME}\n"
            "---\n"
            "[1] Scan for Devices\n"
            "[2] Discover Device Services\n"
            "[3] Monitor Single device\n"
            "[4] Monitor All Devices in Range\n"
            "\\[q] Quit\n"
            "---"
        )
        console.print(menu_text, highlight=False)
        key = await asyncio.to_thread(readchar.readkey)

        match key.lower():
            case "1":
                scan_timeout = await self.interaction_manager.read_user_input(input_type="scan")
                if scan_timeout is not None:
                    await self.scan_manager.scan(scan_timeout=int(scan_timeout))
            case "2":
                device_address = await self.interaction_manager.read_user_input(input_type="discovery")
                if device_address is not None:
                    await self.discovery_manager.discover(device_address=device_address)
            case "3":
                device_address = await self.interaction_manager.read_user_input(input_type="monitoring")
                if device_address is not None:
                    await self.monitoring_manager.monitor(device_address=device_address)
            case "4":
                await self.monitoring_manager.monitor()
            case "q":
                await self.shutdown()
    
    async def shutdown(self) -> None:
        self.is_running = False
        self.logger.info("Clearing write queue...")
        try:
            await self.storage_manager.shutdown_queue_worker()
        except Exception as e:
            self.logger.error("Failed to clear write queue: %s", e)
        self.logger.info("Exiting...")
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

if __name__ == "__main__":
    app = BlueScopeApp()
    try:
        asyncio.run(app.run())
    except (KeyboardInterrupt, SystemExit):
        pass