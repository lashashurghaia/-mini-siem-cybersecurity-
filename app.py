import streamlit as st
import pandas as pd
import joblib
import time
import json
import os
import sqlite3
from datetime import datetime

st.set_page_config(page_title="Mini-SIEM პლატფორმა", layout="wide")

st.markdown("""
    <style>
    .stApp { background-color: #0f172a; color: #f1f5f9; }
    [data-testid="stSidebar"] { background-color: #1e293b; }
    [data-testid="stSidebar"] .stRadio label { color: #f1f5f9 !important; }
    .stButton>button { background-color: #334155; color: #ffffff; border-radius: 6px; border: 1px solid #475569; font-weight: 500; padding: 8px 20px; transition: 0.2s; }
    .stButton>button:hover { background-color: #475569; border-color: #64748b; }
    h1, h2, h3, h4, h5, h6 { color: #f8fafc !important; font-family: 'Segoe UI', sans-serif; }
    .stMarkdown, p, span { color: #cbd5e1; }
    </style>
    """, unsafe_allow_html=True)

st.title("ინტელექტუალური ქსელური Mini-SIEM პლატფორმა")
st.markdown("---")

def init_db():
    conn = sqlite3.connect("siem_logs.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS security_logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, time TEXT, status TEXT, details TEXT)''')
    conn.commit()
    conn.close()

init_db()

def log_to_db(ip, current_time, status, details):
    conn = sqlite3.connect("siem_logs.db")
    c = conn.cursor()
    c.execute("INSERT INTO security_logs (ip, time, status, details) VALUES (?, ?, ?, ?)", 
              (ip, current_time, status, details))
    conn.commit()
    conn.close()

@st.cache_resource
def load_resources():
    model = joblib.load("cyber_model.pkl")
    metrics = None
    if os.path.exists("metrics.json"):
        with open("metrics.json", "r") as f:
            metrics = json.load(f)
    return model, metrics

try:
    model, metrics = load_resources()
except FileNotFoundError:
    st.error("მოდელი ვერ მოიძებნა. ჯერ გაუშვით train.py")
    st.stop()

menu = st.sidebar.radio("მართვის პანელი", 
    ["რეალური დროის მონიტორინგი", "მოდელის ანალიტიკა", "პრევენციის ლოგები (DB)"]
)

attack_names = {0: "ნორმალური ტრაფიკი", 1: "DDoS შეტევა", 2: "Brute-Force შეტევა", 3: "Port Scan შეტევა"}

if menu == "რეალური დროის მონიტორინგი":
    st.subheader("ქსელური ტრაფიკის ანალიზი რეალურ დროში")
    
    if st.button("ტრაფიკის სიმულაციის გაშვება", key="live_sim"):
        if os.path.exists("network_traffic.csv"):
            df_traffic = pd.read_csv("network_traffic.csv")
            samples = df_traffic.sample(5).to_dict(orient="records")
            fake_ips = ["192.168.1.50", "185.220.101.5", "10.0.0.12", "94.23.45.112", "172.16.5.88"]
            
            for i, packet in enumerate(samples):
                ip = fake_ips[i]
                features = pd.DataFrame([{
                    "duration": packet["duration"],
                    "packet_count": packet["packet_count"],
                    "byte_count": packet["byte_count"],
                    "port": packet["port"],
                    "protocol": packet["protocol"]
                }])
                
                prediction = model.predict(features)[0]
                attack_type = attack_names[prediction]
                current_time = datetime.now().strftime("%H:%M:%S")
                
                if prediction != 0:
                    st.markdown(f"""
                        <div style="background-color: #2d1a1a; border: 1px solid #7f1d1d; padding: 14px; border-radius: 6px; margin-bottom: 10px;">
                            <span style="color: #fca5a5; font-weight: 600; font-size: 15px;">კრიტიკული საფრთხე: {attack_type}</span><br>
                            <span style="color: #cbd5e1;"><b>წყარო IP:</b> {ip} | <b>პორტი:</b> {int(packet['port'])} | <b>დრო:</b> {current_time}</span><br>
                            <span style="color: #fca5a5; font-size: 13px;"><b>სისტემის რეაგირება:</b> წყარო დაიბლოკა. მონაცემები შეინახა ბაზაში.</span>
                        </div>
                    """, unsafe_allow_html=True)
                    log_to_db(ip, current_time, "დაბლოკილი", attack_type)
                else:
                    st.markdown(f"""
                        <div style="background-color: #14241a; border: 1px solid #064e3b; padding: 14px; border-radius: 6px; margin-bottom: 10px;">
                            <span style="color: #a7f3d0; font-weight: 600; font-size: 15px;">{attack_type}</span><br>
                            <span style="color: #cbd5e1;"><b>წყარო IP:</b> {ip} | <b>პორტი:</b> {int(packet['port'])} | მოცულობა: {int(packet['byte_count'])} ბაიტი</span>
                        </div>
                    """, unsafe_allow_html=True)
                time.sleep(1)
        else:
            st.warning("ფაილი 'network_traffic.csv' არ არსებობს.")

elif menu == "მოდელის ანალიტიკა":
    st.subheader("Random Forest მოდელის მეტრიკები")
    if metrics:
        st.metric(label="მოდელის საბაზისო სიზუსტე (Accuracy)", value=f"{metrics['accuracy'] * 100:.2f}%")
        st.markdown("---")
        st.write("Confusion Matrix (მულტიკლასობრივი):")
        cm = metrics['confusion_matrix']
        st.table(cm)
        st.caption("რიგები: რეალური კლასები (ნორმალური, DDoS, Brute-Force, Port Scan). სვეტები: მოდელის პროგნოზი.")
    else:
        st.info("მეტრიკები ვერ მოიძებნა.")

elif menu == "პრევენციის ლოგები (DB)":
    st.subheader("SQLite მონაცემთა ბაზის ჟურნალი")
    conn = sqlite3.connect("siem_logs.db")
    df_logs = pd.read_sql_query("SELECT * FROM security_logs ORDER BY id DESC", conn)
    conn.close()
    
    if not df_logs.empty:
        st.dataframe(df_logs, use_container_width=True)
    else:
        st.info("ბაზაში ინციდენტები ჯერ არ ფიქსირდება.")