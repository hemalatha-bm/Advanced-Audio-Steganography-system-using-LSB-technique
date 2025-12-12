# Advanced-Audio-Steganography-system-using-LSB-technique
Built an advanced Audio Steganography system using the LSB technique to securely hide messages in audio without quality loss. Developed with Python Tkinter, SQLite authentication, and secure email support. Includes Hide Text, Extract Text, and Play Audio features for safe and seamless secret communication.

A secure steganography system that hides and extracts secret messages inside audio files using the Least Significant Bit (LSB) algorithm. Includes GUI, authentication, hidden file storage, multi-format audio support, and secure email transmission.

**1.Overview**

This project implements advanced audio steganography using the LSB (Least Significant Bit) technique to hide secret messages within audio files without altering the sound quality.

It includes:

This project features a user-friendly GUI developed with Python Tkinter and includes secure authentication using SQLite with hashed passwords. It supports multiple audio formats and stores both encoded audio files and extracted messages inside hidden output folders for enhanced privacy. The system also automates email delivery by sending the encoded audio along with the secret key directly to the receiver. Overall, the application is designed to ensure secure communication, protect sensitive data, and provide a simple, efficient user experience.

**2. Features**

The system allows users to securely hide secret text inside audio files and extract it later using a secret key. It includes Play and Stop audio options to verify sound quality before and after encoding and supports multiple audio formats for flexibility. Encoded audio files and extracted messages are automatically stored in hidden folders for added privacy. The application features secure login and registration, a clean Tkinter-based GUI, and automatic email delivery of the encoded audio along with the secret key, ensuring a smooth and secure communication workflow.

**3. System Modules**

The system provides secure user authentication, allowing users to register and log in with passwords hashed using hashlib/bcrypt to ensure only authorized access. The Hide Text feature embeds secret messages into audio files using the LSB method, stores the encoded audio in a hidden output folder, and automatically sends the encoded file along with a secret key to the receiver via email. The Extract Text module retrieves hidden messages from encoded audio using the secret key and saves the extracted text as a hidden file for added confidentiality. The application also includes Play/Stop Audio functionality, supporting multiple formats such as WAV and MP3, enabling users to verify that the audio quality remains unaffected. A secure Logout option is provided to safely end the session and prevent unauthorized access to previous user activity.

**4. How It Works (LSB Algorithm)**

The hiding process begins by converting the secret message into a binary format, which is then embedded into the least significant bits of the audio samples. The modified audio is saved as an encoded output, and a secret key is generated to allow secure extraction. During the extraction process, the encoded audio is read, and the least significant bits are retrieved using the secret key. These bits are then reconstructed into the original binary message, converted back into readable text, and saved securely inside a hidden folder, ensuring confidentiality and protection of the hidden information.


**Why LSB?**

No change in audio quality
Hard to detect
Lightweight & efficient
 
**5. Installation & Setup**
**Prerequisites:**

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

Users begin by registering an account and logging in to access the system’s features. The Hide Text module allows users to upload an audio file, enter a secret message, and provide sender and receiver email addresses; upon encoding, the audio is saved in a hidden folder and automatically emailed to the receiver. The Extract Text module enables users to upload the encoded audio, enter the secret key, and view the extracted message, which is also stored securely in a hidden folder. The Play Audio feature allows users to verify sound quality before and after embedding, ensuring audio integrity. Finally, the Logout function safely exits the system, preventing unauthorized access and maintaining session security.

**7. Screenshots**

![Pic1](https://github.com/user-attachments/assets/6be362db-e452-478d-b057-c6cf540c64a8)

![Pic2](https://github.com/user-attachments/assets/b03bc74b-0694-4d39-ba72-71d6624f9adc)

![Pic3](https://github.com/user-attachments/assets/8e37d065-7a7f-4d6b-ae14-3ffc88fb6019)

![pic4](https://github.com/user-attachments/assets/eb261bf4-c211-47cc-b830-ea39ec4a5197)



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

**9. Acknowledgments**

This project was developed as part of a learning initiative .
Contributions and suggestions are welcome!!
