# CyberSec

A practical web platform for easy way to use cybersecurity tools and concepts:  
- Network scanning(open ports, services etc.) 
- Cryptography (encryption, decryption, hashing)  
- Social engineering awareness tests  
- AI assistant  
- Directory bruteforcing 
- Personal history of all actions and admin panel

### Installation and Launch Instructions

1) clone repository: git clone https://github.com/dawaze/CyberSec_Release
2) install requirements: pip install -r requirements.txt
3) initiliaze database: python init_db.py
4) turn on AI: open app.py and on line 21 set your key -> GROQ_API_KEY = "PUT_GROQ_API_KEY_RIGHT_HERE"
5) turn on server: python app.py
6) in browser: 127.0.0.1:4000