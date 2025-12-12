# Advanced-Audio-Steganography-system-using-LSB-technique
Built an advanced Audio Steganography system using the LSB technique to securely hide messages in audio without quality loss. Developed with Python Tkinter, SQLite authentication, and secure email support. Includes Hide Text, Extract Text, and Play Audio features for safe and seamless secret communication.

A secure steganography system that hides and extracts secret messages inside audio files using the Least Significant Bit (LSB) algorithm. Includes GUI, authentication, hidden file storage, multi-format audio support, and secure email transmission.

**1. Overview
**
This project implements advanced audio steganography using the LSB (Least Significant Bit) technique to hide secret messages within audio files without altering the sound quality.

It includes:

✔ A user-friendly GUI built with Python Tkinter.
✔ Secure authentication using SQLite & hashed passwords.
✔ Multi-format audio support.
✔ Hidden output folders for storing encoded audio & extracted messages.
✔ Automatic email sending of encoded audio + secret key.
✔ Designed for secure communication, data privacy, and simple usability.

**2. Features**

✔ Hide secret text inside audio files
✔ Extract hidden text using a secret key
✔ Play/Stop audio (before and after encoding)
✔ Supports multiple audio formats
✔ Stores encoded files & extracted messages in hidden folders
✔ Secure login & registration
✔ Automatically emails encoded audio + secret key
✔ Simple, clean Tkinter GUI

**3. System Modules**
** User Authentication**

Users register and log in securely
Passwords hashed using hashlib/bcrypt
Ensures only authorized access

**Hide Text**

Embeds secret messages into audio using LSB
Saves encoded audio in a hidden output folder
Sends encoded audio + secret key to the receiver via email

**Extract Text**

Extracts text from encoded audio using the secret key
Saves extracted message as a hidden text file

**Play / Stop Audio**

Plays both original and encoded audio
Supports multiple formats (WAV, MP3, etc.)
Confirms that audio quality remains unchanged

**Logout**

Safely ends session
Prevents unauthorized access to previous user’s activity

****4. How It Works (LSB Algorithm)**
Hiding Process:**

Convert the secret message into binary
Replace the least significant bits of audio samples with message bits
Save modified audio as encoded output
Generate a secret key for extraction

**Extraction Process:**

Read encoded audio samples
Extract LSB bits based on the secret key
Reconstruct binary message → convert to readable text
Save extracted message inside a hidden folder

**Why LSB?**

No change in audio quality
Hard to detect
Lightweight & efficient

** 5. Installation & Setup
Prerequisites:**

Python 3.8+

**Required libraries:**

pip install tkinter
pip install bcrypt
pip install pillow
pip install playsound

1.Clone the Repository:
2.Run the Application:
CMD:python main.py

**6. How to Use**
1. Register/Login

Create an account
Log in to access features

2. Hide Text

Upload audio
Enter secret message
Provide sender/receiver email
Encode → audio saved in hidden folder → auto-email sent

3. Extract Text

Upload encoded audio
Enter secret key
View extracted message → saved in hidden folder

4. Play Audio

Check sound quality before/after embedding

5. Logout

Safely exit the system

**7. Screenshots**


![Pic1](https://github.com/user-attachments/assets/6be362db-e452-478d-b057-c6cf540c64a8)


**8. Technology Stack**
Programming & Libraries

Python
Tkinter (GUI)
Wave, Struct (audio processing)
smtplib, email (secure email sending)
Playsound / Pydub
Security
SQLite (database)
Password Security Using PBKDF2
