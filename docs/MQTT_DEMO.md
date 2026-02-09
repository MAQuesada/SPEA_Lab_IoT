# MQTT demo: sensor simulator and subscriber

Steps to run the temperature/humidity sensor simulator and the MQTT subscriber client.

**Broker:** `mqtt://public:public@public.cloud.shiftr.io`  
**Topic:** `spea-lab-iot/sensor`

---

## Step 1: Install dependencies

From the project root:

```bash
uv sync
```

---

## Step 2: Run the subscriber

In a terminal, start the subscriber so it is ready to receive messages:

```bash
uv run python scripts/mqtt_subscriber.py
```

Leave this running. You should see:

- `Connected to broker public.cloud.shiftr.io`
- `Subscribed to topic 'spea-lab-iot/sensor' (Ctrl+C to stop)`

---

## Step 3: Run the sensor simulator

In a **second** terminal, start the sensor simulator:

```bash
uv run python scripts/mqtt_sensor.py
```

The sensor will publish a JSON payload every 5 seconds with `temperature` (°C) and `humidity` (%). The subscriber terminal will print each received message.

---

## Step 4: Stop

- Press **Ctrl+C** in the sensor terminal to stop publishing.
- Press **Ctrl+C** in the subscriber terminal to stop listening.

---

## Payload format

Each message is a JSON object, for example:

```json
{
  "temperature": 28.3,
  "humidity": 62.1,
  "unit_temp": "celsius",
  "unit_humidity": "%"
}
```

The simulator uses a baseline value and adds a random deviation (±10°C for temperature, ±10% for humidity) to mimic real sensor noise.
