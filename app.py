import streamlit as st
import pandas as pd
import joblib
import time
import json
import os
import sqlite3
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np
import random

# საიტის კონფიგურაცია და სტილები
st.set_page_config(page_title="Mini-SIEM პლატფორმა", layout="wide")
st.markdown("""
    <style>
    /* მთლიანი აპლიკაციის ფონი და ტექსტი */
    .stApp { background-color: #0f172a; color: #f1f5f9; }

    /* სიდიარეის მენიუ */
    [data-testid="stSidebar"] { background-color: #1e293b; }
    [data-testid="stSidebar"] .stRadio label { color: #f1f5f9 !important; }

    /* ღილაკების სტილი */
    .stButton>button { 
        background-color: #334155; 
        color: #ffffff; 
        border-radius: 6px; 
        border: 1px solid #475569; 
        font-weight: 500; 
        padding: 8px 20px; 
        transition: 0.2s; 
    }
    .stButton>button:hover { background-color: #475569; border-color: #64748b; }

    /* სათაურების სტილი */
    h1, h2, h3, h4, h5, h6 { 
        color: #f8fafc !important; 
        font-family: 'Segoe UI', sans-serif; 
    }

    /*  ტექსტის სტილი */
    .stMarkdown, p, span { color: #cbd5e1; }

    /* მონაცემთა ცხრილების სტილი */
    .dataframe tbody tr:nth-child(odd) { background-color: #1e293b; }
    .dataframe tbody tr:nth-child(even) { background-color: #2d3748; }
    </style>
    """, unsafe_allow_html=True)

st.title("ინტელექტუალური ქსელური Mini-SIEM პლატფორმა")
st.markdown("---")

# მონაცემთა ბაზის ინიციალიზაცია
def init_db():
    conn = sqlite3.connect("siem_logs.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS security_logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, time TEXT, status TEXT, details TEXT)''')
    conn.commit()
    conn.close()

init_db()

# ინციდენტის ლოგირების ფუნქცია
def log_to_db(ip, current_time, status, details):
    conn = sqlite3.connect("siem_logs.db")
    c = conn.cursor()
    c.execute("INSERT INTO security_logs (ip, time, status, details) VALUES (?, ?, ?, ?)", 
              (ip, current_time, status, details))
    conn.commit()
    conn.close()

@st.cache_resource
def load_resources():
    model = None
    metrics = None
    if os.path.exists("cyber_model.pkl"):
        model = joblib.load("cyber_model.pkl")
    if os.path.exists("metrics.json"):
        with open("metrics.json", "r") as f:
            metrics = json.load(f)
    return model, metrics

model, metrics = load_resources()

# თუ მოდელი არ არსებობს
if model is None:
    st.error("მოდელი 'cyber_model.pkl' ვერ მოიძებნა საქაღალდეში. გთხოვთ, ჯერ გაუშვათ train.py მოდელის დასატრენინგებლად!")
    st.stop()

# მთავარი მენიუ
menu = st.sidebar.radio("მართვის პანელი", 
    ["რეალური დროის მონიტორინგი", "პრევენციის ისტორია", "მოდელის ანალიტიკა"]
)

attack_names = {0: "ნორმალური ტრაფიკი", 1: "DDoS შეტევა", 2: "Brute-Force შეტევა", 3: "Port Scan შეტევა"}

severity_levels = {
    1: "მაღალი",
    2: "საშუალო",
    3: "დაბალი"
}

if menu == "რეალური დროის მონიტორინგი":
    st.subheader("ქსელური ტრაფიკის ანალიზი რეალურ დროში")
    if st.button("ტრაფიკის სიმულაციის გაშვება", key="live_sim"):

        if os.path.exists("network_traffic.csv"):
            df_traffic = pd.read_csv("network_traffic.csv")
            samples = df_traffic.sample(20).to_dict(orient="records")

            for packet in samples:

                if random.random() < 0.3:
                    ip = f"192.168.1.{random.randint(1,254)}"
                else:
                    ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

                features = pd.DataFrame([{
                    "duration": packet["duration"],
                    "packet_count": packet["packet_count"],
                    "byte_count": packet["byte_count"],
                    "port": packet["port"],
                    "protocol": packet["protocol"]
                }])

                prediction = model.predict(features)[0]
                probabilities = model.predict_proba(features)[0]
                confidence = max(probabilities) * 100
                attack_type = attack_names[prediction]
                current_time = datetime.now().strftime("%H:%M:%S")

                if prediction != 0:
                    severity = severity_levels[prediction]
                    st.markdown(f"""
                    <div style="background-color: #2d1a1a; border: 1px solid #7f1d1d; padding: 14px; border-radius: 6px; margin-bottom: 10px;">
                        <span style="color: #fca5a5; font-weight: 700;">კრიტიკული საფრთხე: {attack_type}</span><br>
                        <span style="color: #fca5a5;">საფრთხის დონე: {severity}</span><br>
                        <span style="color: #cbd5e1;"> <b>წყარო IP:</b> {ip} | <b>პორტი:</b> {int(packet['port'])} | <b>დრო:</b> {current_time} </span><br>
                        <span style="color: #fca5a5; font-size: 13px;"> <b>სისტემის რეაგირება:</b> წყარო დაიბლოკა. მონაცემები შეინახა ბაზაში. </span>
                    </div>
                    """, unsafe_allow_html=True)

                    log_to_db(ip, current_time, "დაბლოკილი", attack_type)
                else:
                    st.markdown(f"""
                    <div style="background-color: #14241a; border: 1px solid #064e3b; padding: 14px; border-radius: 6px; margin-bottom: 10px;">
                        <span style="color: #a7f3d0; font-weight: 600; font-size: 15px;">{attack_type} (Safe)</span><br>
                        <span style="color: #cbd5e1;"> <b>წყარო IP:</b> {ip} | <b>პორტი:</b> {int(packet['port'])} | მოცულობა: {int(packet['byte_count'])} ბაიტი </span>
                    </div>
                    """, unsafe_allow_html=True)

                time.sleep(1)
        else:
            st.warning("ფაილი 'network_traffic.csv' არ არსებობს. გთხოვთ, ჯერ გაუშვათ generate_data.py!")

elif menu == "მოდელის ანალიტიკა":
    st.subheader("Random Forest მოდელის მეტრიკები")
    if metrics:
        st.metric(label="მოდელის საბაზისო სიზუსტე (Accuracy)", value=f"{metrics['accuracy'] * 100:.2f}%")
        st.markdown("---")
       
        st.write("Confusion Matrix (მულტიკლასობრივი ცხრილი):")
        cm = metrics['confusion_matrix']
        categories = ["Normal", "DDoS", "Brute-Force", "Port Scan"]
        cm_df = pd.DataFrame(
            cm,
            index=[f"{cat} (რეალური)" for cat in categories],
            columns=[f"{cat} (პროგნოზი)" for cat in categories]
        )
        st.dataframe(cm_df.style.background_gradient(cmap="Blues"), width="stretch")
        st.caption("განმარტება: ცხრილის დიაგონალზე გაფერადებული უჯრები ასახავს მოდელის მიერ სწორად კლასიფიცირებულ შემთხვევებს.")
        st.markdown("---")
       
elif menu == "პრევენციის ისტორია":
    st.subheader("SQLite მონაცემთა ბაზა")
    conn = sqlite3.connect("siem_logs.db")
    df_logs = pd.read_sql_query("SELECT * FROM security_logs ORDER BY id DESC", conn)
    conn.close()

    if not df_logs.empty:
        total_logs = len(df_logs)
        ddos_count = len(df_logs[df_logs["details"] == "DDoS შეტევა"])
        brute_count = len(df_logs[df_logs["details"] == "Brute-Force შეტევა"])
        portscan_count = len(df_logs[df_logs["details"] == "Port Scan შეტევა"])

        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("სულ ინციდენტები", total_logs)
        col2.metric("DDoS", ddos_count)
        col3.metric("Brute Force", brute_count)
        col4.metric("Port Scan", portscan_count)

        st.dataframe(df_logs, width="stretch")
    else:
        st.info("ბაზაში ინციდენტები ჯერ არ ფიქსირდება.")