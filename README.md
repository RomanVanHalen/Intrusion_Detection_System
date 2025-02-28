
🚨 Network-Based Intrusion Detection System (IDS)
This is a simple but effective network-based Intrusion Detection System (IDS) developed to detect suspicious activities, such as port scanning and unusual network behavior, in real-time. It serves as an educational project to understand how attackers probe networks and how defenders can spot these attempts.

🔗 Features
✅ Scans for TCP SYN scans (half-open scans)
✅ Detects UDP scans (open and closed port discovery)
✅ Monitors for full port sweeps across a range of IPs or a single target
✅ Real-time alerts when suspicious activity is detected
✅ Simple live dashboard to view scan results

💻 Technologies Used
Python (Core logic)
Scapy (Packet crafting & sniffing)
Socket Programming (For port scanning and communication)
Basic Visualization (Using terminal outputs)

🚀 How It Works
This IDS captures incoming and outgoing packets, analyzes the flags, source/destination ports, and frequencies, and compares them against known patterns of malicious scans. If it detects suspicious activity, it immediately logs the event and triggers an alert.

"Wireshark sees everything, but says nothing. The IDS doesn’t see everything, but screams when something’s wrong."
