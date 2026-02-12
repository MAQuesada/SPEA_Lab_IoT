# R1: Enrollable devices and platform manager

Platform maintains a dict of allowed devices (device_id → PIN). Devices pair with `action: "pairing"` and PIN; once enrolled, they publish data to `iot/data`. Platform republishes to `iot/feed` including `device_id` so subscribers can identify the sensor.

## Topics

| Topic | Publisher | Subscriber | Purpose |
|-------|-----------|------------|---------|
| `iot/enroll` | Devices | Platform | Pairing request: `{"action": "pairing", "device_id": "...", "pin": "..."}` |
| `iot/enroll/response` | Platform | Devices | Enrollment response: `{"device_id": "...", "status": "enrolled", "data_topic": "iot/data"}` |
| `iot/data` | Devices | Platform | Sensor data (device_id, temperature, humidity, ...) |
| `iot/feed` | Platform | Subscribers | Relayed data including `device_id` for identification |

---

## Step 1: Install and run the platform

From the project root:

```bash
uv sync
uv run python -m spea_lab_iot.platform
```

Optional: start with log mode on:

```bash
PLATFORM_LOG=1 uv run python -m spea_lab_iot.platform
```

Console menu:

- **1. Add device** – Enter device_id and PIN; that device can then pair with that PIN.
- **2. Remove device** – Enter device_id; removes from allowed and enrolled. That device can no longer pair or send data.
- **3. Toggle log mode** – Turn on/off detailed logging.
- **4. Quit** – Stop the platform.

The platform starts with one allowed entry: `default` → `PLATFORM_DEFAULT_PIN` (from env). Keypad devices use that PIN to pair.

---

## Step 2a: Keypad device

In another terminal:

```bash
uv run python -m spea_lab_iot.device_keypad
```

When prompted, enter the **platform default PIN** (value of `PLATFORM_DEFAULT_PIN`). The device pairs once and then publishes temperature/humidity to `iot/data`. The platform relays to `iot/feed` including the `sensor_id`

---

## Step 2b: Screen device

1. **Run the screen device** (it generates a random 6-digit PIN at startup and prints it):

   ```bash
   uv run python -m spea_lab_iot.device_screen
   ```

   You will see e.g. `Device ID: sensor-screen-01`, `PIN: 483921`, and "Attempting pairing until enrolled...".

2. **Add the device on the platform**  
   In the platform console: **1. Add device**, then enter:
   - Device ID: `sensor-screen-01` (match `SENSOR_ID` in `device_screen.py`)
   - PIN: the 6-digit value shown on the device (e.g. `483921`).

   The device’s next pairing attempt will succeed; it then publishes data. The platform relays to `iot/feed` including the `sensor_id`.

---

## Step 3: Subscribe to the feed

In a third terminal:

```bash
uv run python -m spea_lab_iot.feed_subscriber
```

You will see messages from `iot/feed` with `device_id`, temperature, and humidity for each sensor.

---

## Summary

- **Platform**: `allowed_devices` dict (device_id → PIN), `"default"` reserved; `enrolled_devices` set; remove = drop from both so device cannot pair or send data.
- **Keypad**: User enters platform PIN; device sends pairing once, then data.
- **Screen**: Device generates a random 6-digit PIN at startup, shows ID and PIN, retries pairing until enrolled, then data.
- **iot/feed**: All relayed messages include `device_id` so subscribers can identify the sensor.
