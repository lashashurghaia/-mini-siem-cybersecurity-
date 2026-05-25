import pandas as pd
import numpy as np
import random

np.random.seed(42)
n_samples = 5000

data = []
for _ in range(n_samples):
    # 0: ნორმალური, 1: DDoS, 2: Brute-Force, 3: Port Scan
    attack_type = np.random.choice([0, 1, 2, 3], p=[0.7, 0.1, 0.1, 0.1])
    
    if attack_type == 0: 
        duration = round(random.uniform(0.1, 5.0), 2)
        packet_count = random.randint(10, 150)
        byte_count = packet_count * random.randint(64, 1500)
        port = random.choice([80, 443])
        protocol = random.choice([1, 2]) # 1:TCP, 2:UDP
    elif attack_type == 1: 
        duration = round(random.uniform(5.0, 20.0), 2)
        packet_count = random.randint(5000, 20000)
        byte_count = packet_count * random.randint(40, 100)
        port = 80
        protocol = 1
    elif attack_type == 2: 
        duration = round(random.uniform(10.0, 60.0), 2)
        packet_count = random.randint(500, 2000)
        byte_count = packet_count * random.randint(100, 300)
        port = 22 
        protocol = 1
    else: 
        duration = round(random.uniform(0.1, 2.0), 2)
        packet_count = random.randint(1000, 5000)
        byte_count = packet_count * 64
        port = random.randint(1024, 65535)
        protocol = 1

    data.append([duration, packet_count, byte_count, port, protocol, attack_type])

df = pd.DataFrame(data, columns=['duration', 'packet_count', 'byte_count', 'port', 'protocol', 'attack_type'])
df.to_csv("network_traffic.csv", index=False)
print("ახალი ბაზა შეიქმნა მულტი-კლას კლასიფიკაციისთვის!")