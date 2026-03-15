"""
Web Dashboard for SPEA Lab IoT.
Allows real-time device enrollment, management, and telemetry monitoring.
"""

import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
import pandas as pd
from threading import Thread
from datetime import datetime

# Centralized configuration import
from spea_lab_iot.config import (
    MQTT_BROKER_HOST, MQTT_BROKER_PORT, MQTT_USER, MQTT_PASSWORD,
    TOPIC_ADMIN_REQ_DEVICES, TOPIC_ADMIN_RES_DEVICES,
    TOPIC_ADMIN_REMOVE, TOPIC_ADMIN_ADD, TOPIC_FEED
)

st.set_page_config(page_title="SPEA Lab IoT", page_icon="🛡️", layout="wide")

# ==================== SHARED STATE ====================
# This prevents Streamlit from blocking the background MQTT thread when saving data
@st.cache_resource
def get_shared_state():
    return {"devices": {}, "sensor_data": []}

shared_state = get_shared_state()

# ==================== MQTT CLIENT ====================
def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        client.subscribe(TOPIC_ADMIN_RES_DEVICES)
        client.subscribe(TOPIC_FEED)
        # Request enrolled devices immediately upon connection
        client.publish(TOPIC_ADMIN_REQ_DEVICES, "get")


def on_message(client, userdata, msg):
    if msg.topic == TOPIC_ADMIN_RES_DEVICES:
        try:
            shared_state["devices"] = json.loads(msg.payload.decode())
        except Exception:
            pass
    elif msg.topic == TOPIC_FEED:
        try:
            data = json.loads(msg.payload.decode())
            
            if "ts" in data:
                # Sensor sends timestamps in seconds; convert to local datetime
                data["timestamp"] = datetime.fromtimestamp(int(data["ts"]))
            else:
                data["timestamp"] = datetime.now()

            shared_state["sensor_data"].append(data)
            
            # Keep only the last 100 data points in memory to avoid overflow
            if len(shared_state["sensor_data"]) > 100:
                shared_state["sensor_data"].pop(0)
        except Exception as e:
            print(f"Error procesando feed: {e}")

@st.cache_resource
def init_mqtt():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2) 
    client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, 60)
    # Run the MQTT loop in a daemon thread so it doesn't block the UI
    Thread(target=client.loop_forever, daemon=True).start()
    return client

mqtt_client = init_mqtt()

# ==================== WEB INTERFACE ====================
st.title("🛡️ SPEA Lab IoT Dashboard")

tab1, tab2 = st.tabs(["⚙️ Device Management", "📊 Data Monitor (Feed)"])

with tab1:
    col_izq, col_der = st.columns([1, 1])
    
    with col_izq:
        st.subheader("➕ Add New Device")
        with st.form("add_device_form", clear_on_submit=True):
            new_id = st.text_input("Device ID (ej. sensor-01)")
            new_pin = st.text_input("Enrollment PIN", type="password")
            new_alg = st.selectbox("Encryption Algorithm", ["AES-GCM", "AES-CBC"])
            submit_btn = st.form_submit_button("Register Device")
            
            if submit_btn and new_id and new_pin:
                payload = json.dumps({"device_id": new_id, "pin": new_pin, "alg": new_alg})
                mqtt_client.publish(TOPIC_ADMIN_ADD, payload)
                st.success(f"Sending request for {new_id}...")
                time.sleep(0.5)
                mqtt_client.publish(TOPIC_ADMIN_REQ_DEVICES, "get")
                st.rerun()

    with col_der:
        st.subheader("📡 Active Devices")
        if st.button("🔄 Refresh List"):
            mqtt_client.publish(TOPIC_ADMIN_REQ_DEVICES, "get")
            time.sleep(0.5)
            st.rerun()

        # Read from the shared state dictionary
        devices = shared_state["devices"]
        if not devices:
            st.info("There are no devices enrolled at this time.")
        else:
            for device_id, info in devices.items():
                c1, c2, c3 = st.columns([2, 2, 1])
                c1.write(f"`{device_id}`")
                c2.write(f"`{info.get('alg', 'N/A')}`") 
                if c3.button("🗑️", key=f"del_{device_id}"):
                    payload = json.dumps({"device_id": device_id})
                    mqtt_client.publish(TOPIC_ADMIN_REMOVE, payload)
                    time.sleep(0.5)
                    mqtt_client.publish(TOPIC_ADMIN_REQ_DEVICES, "get")
                    st.rerun()

with tab2:
    st.subheader("📊 Real-Time Telemetry Monitor")
    
    if st.button("🔄 Update Data"):
        st.rerun()
        
    sensor_data = shared_state["sensor_data"]
    # Only pick up devices that are CURRENTLY enrolled
    enrolled_devices = list(shared_state["devices"].keys())
    
    if not sensor_data or not enrolled_devices:
        st.info("Waiting for devices to enroll and send data...")
    else:
        df = pd.DataFrame(sensor_data)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        
        dispositivo_seleccionado = st.selectbox(
            "🎛️ Select a single device to view:",
            options=enrolled_devices
        )
        
        # Filter the dataframe to isolate only the selected device's data
        df_filtrado = df[df["device_id"] == dispositivo_seleccionado].copy()
        
        if df_filtrado.empty:
            st.warning(f"No data has been received yet for {dispositivo_seleccionado}.")
        else:
            st.write(f"### 📋 Latest readings from `{dispositivo_seleccionado}`")
            display_df = df_filtrado[["timestamp", "temperature", "humidity"]].copy()
            display_df["timestamp"] = display_df["timestamp"].dt.strftime('%H:%M:%S')
            st.dataframe(display_df.tail(10))
            
            if "temperature" in df_filtrado.columns:
                st.write("### 🌡️ Temperature History")
                
                chart_df = df_filtrado.set_index("timestamp")[["temperature"]]
                chart_df.index = chart_df.index.strftime('%H:%M:%S')
                
                st.line_chart(chart_df)