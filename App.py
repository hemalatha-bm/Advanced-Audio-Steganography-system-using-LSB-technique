import tkinter as tk
from tkinter import messagebox, filedialog
import hashlib, secrets, wave, struct, math, os, ssl, subprocess, sys, smtplib, tempfile, shutil
from array import array
from email.message import EmailMessage
from PIL import Image, ImageTk
import sqlite3 # Import for database management
# --- Fix Python 3.12 wave module __del__ bug (avoids AttributeError at exit) ---
def safe_del(self):
    try:
        self.close()
    except AttributeError:
        pass

wave.Wave_write.__del__ = safe_del
import warnings
warnings.filterwarnings(
    "ignore",
    message="pkg_resources is deprecated as an API",
    category=UserWarning
)

import pygame

# For audio playback (using pygame instead of simpleaudio)
try:
    # IMPORTANT: This module must be installed manually using: pip install pygame
    import pygame
    pygame.mixer.init()
except ImportError:
    pygame = None
    print("WARNING: pygame module not found. Audio playback functionality is disabled.")

# For audio file format conversion (MP3/OGG/etc -> WAV)
try:
    from pydub import AudioSegment
    PYDUB_AVAILABLE = True
    AudioSegment.converter = r"C:\Users\hemal\Downloads\ffmpeg-8.0-essentials_build (1)\ffmpeg-8.0-essentials_build\bin\ffmpeg.exe"

except Exception:   
    AudioSegment = None
    PYDUB_AVAILABLE = False
    print("WARNING: pydub module not found. Multi-format audio support is disabled. Install with: pip install pydub and ensure ffmpeg is installed and on PATH.")

# ================================================================
#                       SQLITE DATABASE SETUP
# ================================================================
USERS_DB = 'stego_users.db'

def initialize_db():
    """Initializes the SQLite database and creates the users table if it doesn't exist."""
    try:
        conn = sqlite3.connect(USERS_DB)
        cursor = conn.cursor()
        # The table stores username (TEXT, UNIQUE), password hash (BLOB), and salt (BLOB)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
        # Use messagebox for user visibility in the GUI
        try:
            messagebox.showerror("Database Error", f"Failed to initialize database: {e}")
        except Exception:
            pass
    finally:
        if conn:
            conn.close()

def hash_password(password: str, salt: bytes = None):
    """Generates a salt and hash for a password using PBKDF2."""
    if salt is None:
        salt = secrets.token_bytes(16)
    # Using 100,000 iterations for security
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode('utf-8'), salt, 100000)
    return salt, pw_hash

def register_user(username: str, password: str) -> bool:
    """Registers a new user in the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(USERS_DB)
        cursor = conn.cursor()

        # Check if user already exists
        cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            return False # User already exists

        # Hash and store credentials
        salt, pw_hash = hash_password(password)
        cursor.execute(
            'INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)',
            (username, salt, pw_hash)
        )
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"SQLite registration error: {e}")
        try:
            messagebox.showerror("Database Error", f"Registration failed due to database error: {e}")
        except Exception:
            pass
        return False
    finally:
        if conn:
            conn.close()

def verify_user(username: str, password: str) -> bool:
    """Verifies a user's password against the stored hash in the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(USERS_DB)
        cursor = conn.cursor()

        cursor.execute(
            'SELECT salt, password_hash FROM users WHERE username = ?', 
            (username,)
        )
        result = cursor.fetchone()

        if not result:
            return False # User not found

        salt, stored_hash = result

        # Re-hash the provided password using the stored salt
        _, pw_hash = hash_password(password, salt)

        # Secure comparison of the hash
        return secrets.compare_digest(pw_hash, stored_hash)
    except sqlite3.Error as e:
        print(f"SQLite verification error: {e}")
        try:
            messagebox.showerror("Database Error", f"Login failed due to database error: {e}")
        except Exception:
            pass
        return False
    finally:
        if conn:
            conn.close()

# ================================================================
#                      GLOBAL CONFIGURATION
# ================================================================
OUTPUT_BASE_DIR = r"D:\RIT-Academics\Cybersecurity_Intern\Supraja_Inern_Project_AudioSteg\Output"

# Ensure the folder exists at program start
os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

# ================================================================
#                        WAV GENERATOR
# ================================================================
def generate_sine_wave(filename, duration=1.0, freq=440.0, samplerate=44100, amplitude=16000):
    """Generates a simple sine wave WAV file for testing purposes."""
    n_samples = int(samplerate * duration)
    # Using 'h' for signed 16-bit integers
    samples = array('h') 
    for i in range(n_samples):
        value = int(amplitude * math.sin(2 * math.pi * freq * (i / samplerate)))
        samples.append(value)
    
    # Handle endianness
    if sys.byteorder == 'big':
        samples.byteswap()
            
    wav_file = None
    try:
        # Open and write the WAV file
        with wave.open(filename, 'wb') as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(samplerate)
            wav_file.writeframes(samples.tobytes())
    finally:
        # Workaround for Python 3.12 'wave' module bug causing AttributeError on cleanup
        if wav_file and hasattr(wav_file, '_file'):
            del wav_file._file
            
    print(f"{filename} generated successfully!")

# ================================================================
#                      STEGANOGRAPHY CORE
# ================================================================
APP_SIGNATURE = b"ASTG"
HEADER_LEN_BYTES = 8
BITS_PER_BYTE = 8
STORED_KEY = None  # temporary in-memory key

def _bytes_to_bits(b: bytes):
    """Converts a bytes object into a list of individual bits (0 or 1)."""
    bits = []
    for byte in b:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def _bits_to_bytes(bits):
    """Converts a list of bits back into a bytes object."""
    if len(bits) % 8 != 0:
        # Should not happen if data is correctly structured
        raise ValueError("Number of bits is not a multiple of 8.")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | (bit & 1)
        out.append(byte)
    return bytes(out)

def _read_wav_samples(path):
    """Reads all 16-bit samples from a WAV file."""
    with wave.open(path, 'rb') as w:
        params = w.getparams()
        nchannels, sampwidth, framerate, nframes, comptype, compname = params
        if sampwidth != 2 or comptype != 'NONE':
            raise ValueError("Only uncompressed 16-bit PCM WAV is supported.")
        frames = w.readframes(nframes)
    
    samples = array('h')
    samples.frombytes(frames)
    if sys.byteorder == 'big':
        samples.byteswap()
    return params, samples

def safe_write_wav(path, params, samples):
    """Write WAV safely, avoids Python 3.12 Wave_write __del__ bug."""
    nchannels, sampwidth, framerate, nframes, comptype, compname = params
    samples_to_write = array('h', samples)
    if sys.byteorder == 'big':
        samples_to_write.byteswap()
    
    nframes_new = len(samples_to_write) // nchannels

    w = None
    try:
        w = wave.open(path, 'wb')
        w.setnchannels(nchannels)
        w.setsampwidth(sampwidth)
        w.setframerate(framerate)
        w.setnframes(nframes_new)
        w.writeframes(samples_to_write.tobytes())
    finally:
        if w:
            try:
                w.close()
            except AttributeError:
                pass
            if hasattr(w, '_file'):
                del w._file


def _write_wav_samples(path, params, samples):
    """Writes 16-bit samples back to a new WAV file (safe for Python 3.12)."""
    nchannels, sampwidth, framerate, nframes, comptype, compname = params
    samples_to_write = array('h', samples)
    if sys.byteorder == 'big':
        samples_to_write.byteswap()
    
    nframes_new = len(samples_to_write) // nchannels

    w = None
    try:
        with wave.open(path, 'wb') as w:
            w.setnchannels(nchannels)
            w.setsampwidth(sampwidth)
            w.setframerate(framerate)
            w.setnframes(nframes_new)
            w.writeframes(samples_to_write.tobytes())
    finally:
        if w and hasattr(w, '_file'):
            del w._file


# -----------------------------
# Helpers to support multiple file formats (via pydub)
# -----------------------------
def convert_to_wav(src_path):
    """
    Convert arbitrary audio file to a temporary WAV file (16-bit PCM).
    Returns (wav_path, is_temp) where is_temp==True if a temporary file was created.
    """
    # If source is already a WAV, just return it (but ensure it's 16-bit PCM)
    ext = os.path.splitext(src_path)[1].lower()
    if ext == ".wav":
        return src_path, False

    if not PYDUB_AVAILABLE:
        raise RuntimeError("pydub or ffmpeg not available; cannot convert non-WAV files.")

    # Use pydub to load and export as WAV (16-bit signed PCM)
    try:
        audio = AudioSegment.from_file(src_path)
    except Exception as e:
        raise RuntimeError(f"Could not read input audio file: {e}")

    # Ensure sample width 2 bytes (16-bit) for compatibility
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.wav')
    tmp_name = tmp.name
    tmp.close()
    try:
        # set sample width to 2 bytes
        audio = audio.set_sample_width(2)
        audio.export(tmp_name, format="wav")
    except Exception as e:
        # cleanup temp file
        try:
            os.unlink(tmp_name)
        except Exception:
            pass
        raise RuntimeError(f"Conversion to WAV failed: {e}")

    return tmp_name, True

def safe_remove(path):
    try:
        if path and os.path.exists(path):
            os.unlink(path)
    except Exception:
        pass

# ================================================================
# encode/decode wrappers that accept many input formats
# ================================================================
def encode_any_audio(in_path, message_text, out_wav_path):
    """
    Accepts any supported audio file, converts to WAV if necessary,
    runs encode_wav on the WAV, and writes encoded out_wav_path.
    """
    wav_temp = None
    try:
        wav_src, is_temp = convert_to_wav(in_path) if not in_path.lower().endswith('.wav') else (in_path, False)
        if is_temp:
            wav_temp = wav_src

        # Reuse existing encode_wav implementation which expects WAV path
        return encode_wav(wav_src, message_text, out_wav_path)
    finally:
        # cleanup conversion temp file
        if wav_temp:
            safe_remove(wav_temp)

def decode_any_audio(in_path):
    """
    Accepts any supported audio file, converts to WAV if necessary,
    runs decode_wav on the WAV, returns the decoded string.
    """
    wav_temp = None
    try:
        wav_src, is_temp = convert_to_wav(in_path) if not in_path.lower().endswith('.wav') else (in_path, False)
        if is_temp:
            wav_temp = wav_src
        return decode_wav(wav_src)
    finally:
        if wav_temp:
            safe_remove(wav_temp)

# ================================================================
# encode_wav / decode_wav unchanged except they operate on WAVs
# ================================================================
def encode_wav(in_wav_path, message_text, out_wav_path):
    """Hides a message inside the least significant bit (LSB) of audio samples."""
    params, samples = _read_wav_samples(in_wav_path)
    msg_bytes = message_text.encode('utf-8')
    msg_len = len(msg_bytes)
    # Header: 4-byte signature + 4-byte message length (little-endian unsigned integer)
    header = APP_SIGNATURE + struct.pack('<I', msg_len) 
    payload = header + msg_bytes
    bits = _bytes_to_bits(payload)
    
    if len(bits) > len(samples):
        raise ValueError("Message too large for this audio file. Need more samples.")
    
    samples_out = array('h', samples)
    # Modify the LSB of each sample to store one bit of the message
    for i, bit in enumerate(bits):
        # (samples_out[i] & ~1) clears the LSB (ensures it's 0)
        # | int(bit) sets the LSB to the current message bit
        samples_out[i] = (samples_out[i] & ~1) | int(bit)
        
    _write_wav_samples(out_wav_path, params, samples_out)
    return out_wav_path

def decode_wav(in_wav_path):
    """Extracts a hidden message from the LSB of audio samples."""
    params, samples = _read_wav_samples(in_wav_path)
    header_bits_needed = HEADER_LEN_BYTES * BITS_PER_BYTE
    
    if len(samples) < header_bits_needed:
        raise ValueError("Audio file too short or no hidden data present.")
        
    # Extract the header (signature and length)
    first_bits = [samples[i] & 1 for i in range(header_bits_needed)]
    header_bytes = _bits_to_bytes(first_bits)
    
    signature = header_bytes[:4]
    if signature != APP_SIGNATURE:
        raise ValueError("No hidden data found (signature mismatch).")
        
    # Unpack the message length
    msg_len = struct.unpack('<I', header_bytes[4:8])[0]
    
    total_bits_needed = header_bits_needed + msg_len * 8
    
    if len(samples) < total_bits_needed:
        raise ValueError("Audio file doesn't contain full hidden message.")
        
    # Extract the message bits
    msg_bits = [samples[i] & 1 for i in range(header_bits_needed, total_bits_needed)]
    msg_bytes = _bits_to_bytes(msg_bits)
    
    return msg_bytes.decode('utf-8', errors='replace')

# ================================================================
#                        EMAIL + KEY
# ================================================================
def generate_key():
    """Generates a random URL-safe key."""
    return secrets.token_urlsafe(16)

def send_email_with_attachment(smtp_server, smtp_port, sender_email, sender_password, recipient_email, subject, body_text, attach_path):
    """Sends an email with the encoded WAV file attached."""
    # NOTE: If you are using Gmail or other major providers, 'sender_password' MUST be an App Password
    msg = EmailMessage()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject or "Encoded Audio"
    msg.set_content(body_text or "Please find the encoded audio attached.")
    
    with open(attach_path, 'rb') as f:
        msg.add_attachment(f.read(), maintype='audio', subtype='wav', filename=os.path.basename(attach_path))
        
    context = ssl.create_default_context()
    smtp_port = int(smtp_port)
    
    # Use SMTPS (465) or STARTTLS (587, 25) based on port
    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(sender_email, sender_password)
            server.send_message(msg)
            
# ================================================================
#                             GUI
# ================================================================
def main_window(root):
    """The main application window for steganography functions."""
    root.title("Audio Encode And Decode")
    root.state('zoomed')
    root.configure(bg="black")
    def logout():
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            root.destroy()
            # Return to login screen
            root_login = tk.Tk()
            app = StegoLoginApp(root_login)
            root_login.mainloop()
    
    def play_audio(file_path):
        """Plays the selected audio file using pygame mixer (converting when necessary)."""
        if not pygame:
            messagebox.showerror("Error", "Pygame module not found. Please install it using 'pip install pygame' to enable audio playback.")
            return
        wav_temp = None
        try:
            if not file_path.lower().endswith('.wav'):
                if not PYDUB_AVAILABLE:
                    messagebox.showerror("Error", "Cannot play non-WAV formats because pydub/ffmpeg is not available.")
                    return
                wav_temp, is_temp = convert_to_wav(file_path)
                play_path = wav_temp
            else:
                play_path = file_path

            pygame.mixer.music.load(play_path)
            pygame.mixer.music.play()
        except Exception as e:
            messagebox.showerror("Error", f"Could not play audio: {e}")
        finally:
            # do not remove while playing; user can stop; we remove on stop call if temp
            if wav_temp:
                # schedule removal when playback stops or after some time; here we'll remove immediately if stopped.
                pass

    def stop_audio():
        """Stops currently playing audio."""
        if pygame:
            pygame.mixer.music.stop()

    def show_project_info():
        """Opens the project info PDF file (paths need user adjustment)."""
        # NOTE: This path is hardcoded and may not work on the user's system.
        pdf_path = r"D:\RIT-Academics\Cybersecurity_Intern\Supraja_Inern_Project_AudioSteg\Projectinfo.pdf" 
        
        if os.path.exists(pdf_path):
            try:
                # Platform-specific file opening
                if sys.platform == "win32":
                    os.startfile(pdf_path)
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", pdf_path])
                else:
                    subprocess.Popen(["xdg-open", pdf_path])
            except Exception as e:
                messagebox.showerror("Error", f"Unable to open file: {e}")
        else:
            messagebox.showerror("Error", "Project Info PDF not found at the specified path!")
     
    # ------------------ Hide Text Form ------------------ #
    def hide_text_form():
        """Creates the window for encoding a message."""
        form = tk.Toplevel(root)
        form.title("Hide Message in Audio")
        form.grab_set()
        form.resizable(False, False)
        
        entries = {}
        labels = ["File Path", "Message", "Sender Email", "SMTP Password", "Receiver Email"]
        for i, label in enumerate(labels):
            tk.Label(form, text=label).grid(row=i, column=0, padx=5, pady=5, sticky="w")
            entry = tk.Entry(form, width=48, show="*" if "Password" in label else None)
            entry.grid(row=i, column=1, padx=5, pady=5)
            entries[label] = entry

        def browse_file():
            file_path = filedialog.askopenfilename(parent=form, filetypes=[
                ("Audio Files", "*.wav *.mp3 *.flac *.ogg *.m4a *.aac"),
                ("WAV Files", "*.wav"),
                ("All files", "*.*")
            ])
            if file_path:
                entries["File Path"].delete(0, tk.END)
                entries["File Path"].insert(0, file_path)

        tk.Button(form, text="Browse Files", command=browse_file).grid(row=0, column=2, padx=5, pady=5)

        def hide_action():
            global STORED_KEY
            in_file = entries["File Path"].get().strip()
            message = entries["Message"].get()
            sender = entries["Sender Email"].get().strip()
            password = entries["SMTP Password"].get().strip()
            receiver = entries["Receiver Email"].get().strip()

            if not in_file or not message:
                messagebox.showerror("Error", "File and message required")
                return

            progress_win = tk.Toplevel(form)
            progress_win.title("Encoding...")
            progress_win.geometry("300x80")
            tk.Label(progress_win, text="Encoding...").pack(pady=10)
            progress_win.update()

            try:
                # Use the new, safer output directory based in the user's home folder
                os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)
                out_file = os.path.join(OUTPUT_BASE_DIR, "encoded_output.wav")
                
                # Generate a new key and store it temporarily
                STORED_KEY = generate_key()
                
                # Use conversion wrapper so it supports multiple input formats
                encode_any_audio(in_file, message, out_file)

                # 🔒 Hide the output folder (Windows only)
                if os.name == 'nt':
                    os.system(f'attrib +h "{OUTPUT_BASE_DIR}"')

                if sender and password and receiver:
                    # NOTE: SMTP server details (smtp.gmail.com, 465) are hardcoded.
                    body = f"Here is your encoded audio file.\nSecret Key: {STORED_KEY}"
                    send_email_with_attachment("smtp.gmail.com", 465, sender, password, receiver, "Secret Audio", body, out_file)

                progress_win.destroy()
                messagebox.showinfo("Success", f"Message encoded successfully!")
                form.destroy()
            except Exception as e:
                progress_win.destroy()
                messagebox.showerror("Email/Encoding Error", str(e) + "\n\nIf this is an authentication error, ensure you are using an **App Password** for SMTP.")


        tk.Button(form, text="Hide Text", bg="red", fg="white", width=18, command=hide_action).grid(
            row=len(labels) + 1, column=1, pady=12)

    # ------------------ Extract Text Form ------------------ #
    def extract_text_form():
        """Creates the window for decoding a hidden message."""
        form = tk.Toplevel(root)
        form.title("Extract Message from Audio")
        form.grab_set()
        form.resizable(False, False)

        # File path input
        tk.Label(form, text="File Path").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        entry_file = tk.Entry(form, width=48)
        entry_file.grid(row=0, column=1, padx=5, pady=5)

        def browse_file():
            file_path = filedialog.askopenfilename(
                parent=form,
                filetypes=[
                    ("Audio Files", "*.wav *.mp3 *.flac *.ogg *.m4a *.aac"),
                    ("WAV Files", "*.wav"),
                    ("All files", "*.*")
                ]
            )
            if file_path:
                entry_file.delete(0, tk.END)
                entry_file.insert(0, file_path)

        tk.Button(form, text="Browse Files", command=browse_file).grid(row=0, column=2, padx=5, pady=5)

        # Secret key input
        tk.Label(form, text="Secret Key").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        entry_key = tk.Entry(form, width=48, show="*")
        entry_key.grid(row=1, column=1, padx=5, pady=5)

        def decode_action():
            global STORED_KEY
            file_path = entry_file.get().strip()
            user_key = entry_key.get().strip()

            if not file_path:
                messagebox.showerror("Error", "Please select a valid file")
                return

            if not user_key:
                messagebox.showerror("Error", "Secret key is required")
                return

            try:
                # Validate key
                if STORED_KEY is None or user_key != STORED_KEY:
                    messagebox.showerror("Access Denied", "Invalid Key! Cannot extract the message.")
                    return

                # If key is correct → decode
                message = decode_any_audio(file_path)

                # Save to hidden file instead of showing directly
                hidden_file = os.path.join(OUTPUT_BASE_DIR, "hidden_msg.txt")
                with open(hidden_file, "w", encoding="utf-8") as f:
                    f.write(message)

                # Hide the file (Windows: attrib +h)
                try:
                    subprocess.call(["attrib", "+h", hidden_file])
                except Exception:
                    pass  # silently ignore on non-Windows

                messagebox.showinfo("Success", "Message extracted and saved to hidden file.")
                form.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        # Buttons row
        btn_frame = tk.Frame(form)
        btn_frame.grid(row=2, column=0, columnspan=3, pady=10)

        tk.Button(btn_frame, text="Extract Text", command=decode_action, width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Cancel", command=form.destroy, width=15).pack(side="left", padx=5)

    # ------------------ Play Audio Form ------------------ #
    def play_audio_form():
        """Creates the window for playing an audio file."""
        form = tk.Toplevel(root)
        form.title("Play Audio File")
        form.grab_set()
        form.resizable(False, False)

        tk.Label(form, text="Select Audio File").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        entry_file = tk.Entry(form, width=48)
        entry_file.grid(row=0, column=1, padx=5, pady=5)

        def browse_file():
            file_path = filedialog.askopenfilename(parent=form, filetypes=[
                ("Audio Files", "*.wav *.mp3 *.flac *.ogg *.m4a *.aac"),
                ("WAV Files", "*.wav"),
                ("All files", "*.*")
            ])
            if file_path:
                entry_file.delete(0, tk.END)
                entry_file.insert(0, file_path)

        tk.Button(form, text="Browse Files", command=browse_file).grid(row=0, column=2, padx=5, pady=5)

        def play_selected():
            file_path = entry_file.get().strip()
            if not file_path:
                messagebox.showerror("Error", "Please select an audio file")
                return
            try:
                play_audio(file_path)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(form, text="Play", bg="green", fg="white", width=18, command=play_selected).grid(
            row=1, column=1, pady=10
        )
        tk.Button(form, text="Stop", bg="gray", fg="white", width=18, command=stop_audio).grid(
            row=2, column=1, pady=5
        )

    # ================= UI Layout ================= #
     # ================= UI Layout ================= #
    tk.Button(root, text="Project Info", bg="red", fg="white", font=("Arial", 12, "bold"),
              command=show_project_info).pack(pady=10)
    tk.Label(root, text="Audio Steganography!!!", fg="white", bg="black", font=("Arial", 16)).pack(pady=6)

   

    # Lock image and main buttons
    try:
        lock_img = Image.open(r"D:\RIT-Academics\Cybersecurity_Intern\Supraja_Inern_Project_AudioSteg\logo.png")
        lock_img = lock_img.resize((150, 150))
        lock_photo = ImageTk.PhotoImage(lock_img)
        tk.Label(root, image=lock_photo, bg="black").pack(pady=10)
        root.lock_photo = lock_photo
    except Exception:
        tk.Label(root, text="[Image Missing]", fg="white", bg="black").pack(pady=10)

    button_frame = tk.Frame(root, bg="gray")
    button_frame.pack(pady=20)
    tk.Button(button_frame, text="Hide Text", bg="red", fg="white", width=18,
              font=("Arial", 12, "bold"), command=hide_text_form).pack(pady=8)
    tk.Button(button_frame, text="Extract Text", bg="red", fg="white", width=18,
              font=("Arial", 12, "bold"), command=extract_text_form).pack(pady=8)
    tk.Button(button_frame, text="Play Audio", bg="red", fg="white", width=18,
              font=("Arial", 12, "bold"), command=play_audio_form).pack(pady=8)
     # Logout Button
    tk.Button(root, text="Logout", bg="gray", fg="white", font=("Arial", 12, "bold"),
              width=15, command=logout).pack(pady=10)

    root.mainloop()

# -------------------------
# Login & Register GUI
# -------------------------

# Placeholder class to mimic placeholder text behavior
class PlaceholderEntry(tk.Entry):
    def __init__(self, master=None, placeholder="", placeholder_color='grey', **kwargs):
        super().__init__(master, **kwargs)
        self.placeholder = placeholder
        self.placeholder_color = placeholder_color
        self.default_fg_color = self['fg']
        self.is_placeholder = True

        self.bind("<FocusIn>", self.on_focus_in)
        self.bind("<FocusOut>", self.on_focus_out)
        self.put_placeholder()

    def put_placeholder(self):
        self.delete(0, tk.END)
        self.insert(0, self.placeholder)
        self.config(fg=self.placeholder_color)
        self.is_placeholder = True

    def on_focus_in(self, event):
        if self.is_placeholder:
            self.delete(0, tk.END)
            self.config(fg=self.default_fg_color)
            self.is_placeholder = False
            if self.placeholder == "Password":
                self.config(show='*')

    def on_focus_out(self, event):
        if not self.get():
            self.put_placeholder()
            if self.placeholder == "Password":
                self.config(show='')

class StegoLoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login Page")
        self.root.state('zoomed')
        self.root.configure(bg="black")
        self.login_screen()

    def login_screen(self):
        def login_action(self):
            username = self.username_entry.get().strip()
            password = self.password_entry.get().strip()
            if verify_user(u, p):
               messagebox.showinfo("Success", f"Welcome {u}!")
               self.clear_root()       # Clears login widgets
               main_window(self.root)     # Load main window in the same root
            else:
                messagebox.showerror("Login Failed", "Invalid username or password")

        
        # Center frame
        frame = tk.Frame(self.root, padx=50, pady=50, bg="black", relief=tk.GROOVE, borderwidth=1)
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Project Title
        tk.Label(
            frame, 
            text="Advanced Steganography",
            font=("Helvetica", 24, "bold"),
            bg="black",
            fg="white"
        ).pack(pady=(10, 0))

        tk.Label(
            frame,
            text="using LSB Techniques",
            font=("Helvetica", 14),
            bg="black",
            fg="white"
        ).pack(pady=(0, 20))
        
        # Project Info Button
       # Project Info Button
        def show_info():
            """Opens the project info PDF in the default PDF viewer."""
            pdf_path = r"D:\RIT-Academics\Cybersecurity_Intern\Supraja_Inern_Project_AudioSteg\Projectinfo.pdf"
            
            if os.path.exists(pdf_path):
                try:
                    if sys.platform == "win32":
                        os.startfile(pdf_path)  # Windows
                    elif sys.platform == "darwin":
                        subprocess.Popen(["open", pdf_path])  # macOS
                    else:
                        subprocess.Popen(["xdg-open", pdf_path])  # Linux
                except Exception as e:
                    messagebox.showerror("Error", f"Unable to open PDF: {e}")
            else:
                messagebox.showerror("Error", "Project Info PDF not found at the specified path!")

        # Button to trigger the PDF opening
        tk.Button(
            frame, 
            text="Project Info", 
            command=show_info,
            bg="red",
            fg="white",
            activebackground="darkred",
            relief=tk.FLAT,
            font=("Helvetica", 12)
        ).pack(pady=(0, 20))


        # Login Title
        tk.Label(
            frame,
            text="Login",
            font=("Helvetica", 20, "bold"),
            bg="black",
            fg="white"
        ).pack(pady=(20, 10))

        # Username Input
        username = PlaceholderEntry(frame, placeholder="Username", width=30,
                                           font=("Helvetica", 12), bg="#333333", relief=tk.FLAT,
                                           fg="white", placeholder_color="gray")
        username.pack(pady=10, ipady=8)

        # Password Input
        password = PlaceholderEntry(frame, placeholder="Password", width=30,
                                           font=("Helvetica", 12), bg="#333333", relief=tk.FLAT,
                                           fg="white", placeholder_color="gray")
        password.pack(pady=10, ipady=8)

        def do_login():
            u, p = username.get().strip(), password.get().strip()
            if username.is_placeholder or password.is_placeholder:
                messagebox.showerror("Error", "Both username and password are required")
                return

            # Use the SQLite verification function
            if verify_user(u, p):
                messagebox.showinfo("Success", f"Welcome {u}!")
                self.clear_root()          # Clear login widgets
                main_window(self.root)     # <-- Pass the root window
            else:
                messagebox.showerror("Error", "Invalid credentials or user not found")


        # Login Button
        tk.Button(
            frame, 
            text="Login", 
            command=do_login,
            bg="red", 
            fg="white",
            font=("Helvetica", 14, "bold"),
            relief=tk.FLAT,
            width=25
        ).pack(pady=20, ipady=8)

        # Register Link
        register_link = tk.Label(frame, text="Don't have an account? Register", fg="white", bg="black",
                                       cursor="hand2", font=("Helvetica", 10, "underline"))
        register_link.pack()
        register_link.bind("<Button-1>", lambda e: self.register_screen())

    def register_screen(self):
        self.clear_root()

        # Center frame
        frame = tk.Frame(self.root, padx=50, pady=50, bg="black", relief=tk.GROOVE, borderwidth=1)
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        tk.Label(
            frame, 
            text="Register",
            font=("Helvetica", 20, "bold"),
            bg="black",
            fg="white"
        ).pack(pady=(10, 20))

        username = PlaceholderEntry(frame, placeholder="Username", width=30, font=("Helvetica", 12),
                                            bg="#333333", relief=tk.FLAT, fg="white", placeholder_color="gray")
        username.pack(pady=10, ipady=8)

        password = PlaceholderEntry(frame, placeholder="Password", width=30, font=("Helvetica", 12),
                                            bg="#333333", relief=tk.FLAT, fg="white", placeholder_color="gray")
        password.pack(pady=10, ipady=8)

        def do_register():
            u, p = username.get().strip(), password.get().strip()
            if username.is_placeholder or password.is_placeholder:
                messagebox.showerror("Error", "Both username and password are required")
                return
            
            # Use the SQLite registration function
            if register_user(u, p):
                messagebox.showinfo("Success", "Account created! Please login.")
                self.login_screen()
            else:
                messagebox.showerror("Error", "Username already exists or database error occurred")

        tk.Button(
            frame, 
            text="Register", 
            command=do_register,
            bg="red",
            fg="white",
            font=("Helvetica", 14, "bold"),
            relief=tk.FLAT,
            width=25
        ).pack(pady=20, ipady=8)

        back_link = tk.Label(frame, text="Already a user? Back to Login", fg="white", bg="black",
                                 cursor="hand2", font=("Helvetica", 10, "underline"))
        back_link.pack()
        back_link.bind("<Button-1>", lambda e: self.login_screen())
    
    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

# -------------------------
# Run App
# -------------------------
if __name__ == "__main__":
    # 1. Initialize the SQLite database
    initialize_db()
    
    # 2. Generate a test WAV file if it doesn't exist
    if not os.path.exists("test.wav"):
        generate_sine_wave("test.wav", duration=2.0)
    
    # 3. Start the application
    root = tk.Tk()
    app = StegoLoginApp(root)
    root.mainloop() 
