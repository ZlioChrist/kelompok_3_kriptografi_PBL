import streamlit as st
import os
import json
import base64
import time
import binascii
import pandas as pd
import textwrap
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# --- 1. KONFIGURASI AWAL ---
st.set_page_config(page_title="SecureData | Dark Mode", layout="wide", initial_sidebar_state="expanded")

STORAGE_FOLDER = 'encrypted_storage'
if not os.path.exists(STORAGE_FOLDER):
    os.makedirs(STORAGE_FOLDER)

# --- 2. TEMA VISUAL DARK MODE ---
st.markdown("""
<style>
    /* --- BASE THEME (HITAM & ABU) --- */
    .stApp {
        background-color: #121212; /* Hitam Gelap */
        color: #e0e0e0; /* Putih Gading */
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #000000; /* Hitam Pekat */
        border-right: 1px solid #333;
    }
    
    /* Typography */
    h1, h2, h3 { color: #ffffff !important; font-family: 'Segoe UI', sans-serif; font-weight: 600; }
    p, label { color: #cccccc !important; }
    
    /* --- KOMPONEN INPUT --- */
    .stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] {
        background-color: #1e1e1e !important;
        color: #ffffff !important;
        border: 1px solid #444 !important;
        border-radius: 8px;
    }
    .stTextInput input:focus { border-color: #3498db !important; }

    /* --- TOMBOL --- */
    .stButton > button {
        background-color: #000000;
        color: #ffffff;
        border: 1px solid #ffffff;
        border-radius: 50px;
        padding: 10px 24px;
        font-weight: bold;
        transition: all 0.3s;
    }
    .stButton > button:hover {
        background-color: #3498db; /* UBAH KE BIRU (Tidak Silau) */
        color: #ffffff;
        border-color: #3498db;
        box-shadow: 0 0 15px rgba(52, 152, 219, 0.4);
    }

    /* --- KOTAK INFO --- */
    .info-box {
        background-color: #1e1e1e;
        border-left: 4px solid #3498db;
        padding: 15px;
        margin-bottom: 20px;
        border-radius: 0 8px 8px 0;
        color: #ccc;
    }

    /* --- DESAIN KTP --- */
    .ktp-card {
        /* Gradasi Biru Khas KTP */
        background: linear-gradient(135deg, #89CFF0 0%, #4682B4 100%);
        width: 100%; max-width: 550px;
        border-radius: 12px; padding: 20px;
        color: #000000; /* Teks Hitam Jelas */
        font-family: Arial, Helvetica, sans-serif;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        border: 1px solid #333;
        margin-top: 10px; margin-bottom: 20px;
    }
    .ktp-header { text-align: center; font-weight: bold; font-size: 14px; border-bottom: 2px solid #000; padding-bottom: 5px; margin-bottom: 10px; letter-spacing: 1px; }
    .ktp-title { text-align: center; font-weight: 900; font-size: 18px; margin-bottom: 5px; letter-spacing: 2px; text-transform: uppercase; }
    .ktp-nik { text-align: center; font-size: 24px; font-weight: bold; margin-bottom: 15px; font-family: 'Courier New', monospace; letter-spacing: 2px; color: #000; }
    
    .ktp-body { display: flex; justify-content: space-between; align-items: flex-start; }
    .ktp-text { width: 70%; font-size: 11px; font-weight: 700; line-height: 1.9; color: #000; }
    .ktp-photo-area { width: 28%; text-align: center; display: flex; flex-direction: column; align-items: center; }
    
    .photo-box { 
        width: 100px; height: 130px; 
        background-color: #ddd; border: 1px dashed #666; 
        display: flex; align-items: center; justify-content: center; 
        color: #555; margin-bottom: 10px; font-size: 10px; 
    }
    .sign-box { font-size: 9px; color: #000; margin-top: 5px; }

    /* Tabel KTP */
    table.ktp-tabel { width: 100%; border-collapse: collapse; }
    td { vertical-align: top; padding: 0; color: #000 !important; } 
    .lbl { width: 100px; }
    .sep { width: 10px; text-align: center; }
</style>
""", unsafe_allow_html=True)

# --- 3. LOGIKA KRIPTOGRAFI ---
class HybridCipher:
    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def keys_to_pem(self, private_key, public_key):
        priv_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        pub_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return priv_pem, pub_pem

    def load_keys_from_pem(self, priv_bytes, pub_bytes):
        try:
            private_key = serialization.load_pem_private_key(priv_bytes, password=None, backend=default_backend())
            public_key = serialization.load_pem_public_key(pub_bytes, backend=default_backend())
            return private_key, public_key
        except:
            return None, None

    def encrypt_hybrid(self, data_dict, public_key):
        data_str = json.dumps(data_dict)
        data_bytes = data_str.encode('utf-8')

        # ENKRIPSI AES
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data_bytes) + padder.finalize()
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # ENKRIPSI RSA
        encrypted_aes_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

        package = {
            "iv": base64.b64encode(iv).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8')
        }
        debug_info = {
            "raw_aes_key": binascii.hexlify(aes_key).decode('utf-8'),
            "sample_plain_bytes": padded_data[:16],
            "sample_cipher_bytes": ciphertext[:16]
        }
        return package, debug_info

    def decrypt_hybrid(self, encrypted_package, private_key):
        try:
            iv = base64.b64decode(encrypted_package['iv'])
            ciphertext = base64.b64decode(encrypted_package['ciphertext'])
            enc_aes_key = base64.b64decode(encrypted_package['encrypted_aes_key'])

            aes_key = private_key.decrypt(enc_aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            sample_cipher = ciphertext[:16]
            sample_plain_padded = padded_data[:16]

            unpadder = sym_padding.PKCS7(128).unpadder()
            data_bytes = unpadder.update(padded_data) + unpadder.finalize()
            return json.loads(data_bytes.decode('utf-8')), sample_cipher, sample_plain_padded
        except Exception:
            return None, None, None

def create_df(plain_bytes, cipher_bytes, mode="encrypt"):
    data = []
    limit = min(len(plain_bytes), 16)
    for i in range(limit):
        p_b = plain_bytes[i]
        c_b = cipher_bytes[i]
        char_rep = chr(p_b) if 32 <= p_b <= 126 else "."
        if mode == "encrypt":
            data.append({"Byte Ke": i, "Karakter Asli": char_rep, "Hex Asli": f"{p_b:02X}", "-->": "AES", "Hex Terenkripsi": f"{c_b:02X}"})
        else:
            data.append({"Byte Ke": i, "Hex Masuk": f"{c_b:02X}", "-->": "AES", "Hex Kembali": f"{p_b:02X}", "Karakter": char_rep})
    return pd.DataFrame(data)

# --- 4. STATE ---
if 'gen_priv' not in st.session_state: st.session_state['gen_priv'] = None
if 'gen_pub' not in st.session_state: st.session_state['gen_pub'] = None
if 'keys_created' not in st.session_state: st.session_state['keys_created'] = False
crypto = HybridCipher()

# --- 5. LAYOUT UTAMA ---
st.title(" SISTEM PENGAMANAN DATA")
st.caption("Enkripsi Hibrida: AES-256 (Data) + RSA-2048 (Kunci)")
st.divider()

with st.sidebar:
    st.header("NAVIGASI")
    menu = st.radio("Pilih Modul:", ["1. MANAJEMEN KUNCI", "2. INPUT DATA BARU", "3. DEKRIPSI DATA"])
    st.markdown("---")
    st.caption("© 2025 Disdukcapil Secure")

# --- MENU 1 ---
if menu == "1. MANAJEMEN KUNCI":
    st.subheader(" Generate Kunci RSA")
    st.markdown("<div class='info-box'>Buat kunci master sebelum memulai. Kunci Privat wajib disimpan admin.</div>", unsafe_allow_html=True)
    
    col_btn, col_space = st.columns([1, 2])
    with col_btn:
        if st.button("BUAT KUNCI BARU"):
            priv, pub = crypto.generate_rsa_keys()
            st.session_state['gen_priv'] = priv
            st.session_state['gen_pub'] = pub
            st.session_state['keys_created'] = True
            st.success("Kunci Baru Aktif")

    if st.session_state['keys_created']:
        st.markdown("#### Download Kunci")
        p_priv, p_pub = crypto.keys_to_pem(st.session_state['gen_priv'], st.session_state['gen_pub'])
        c1, c2 = st.columns(2)
        c1.download_button("UNDUH PRIVATE KEY (RAHASIA)", p_priv, "private_key.pem")
        c2.download_button("UNDUH PUBLIC KEY (PUBLIK)", p_pub, "public_key.pem")

# --- MENU 2 ---
elif menu == "2. INPUT DATA BARU":
    st.subheader("Enkripsi Data Kependudukan")
    
    if not st.session_state['keys_created']:
        st.error("SILAKAN BUAT KUNCI DAHULU DI MENU 1")
    else:
        with st.container():
            c1, c2 = st.columns(2)
            nik = c1.text_input("Nomor Induk Kependudukan (NIK)")
            nama = c1.text_input("Nama Lengkap")
            ttl = c1.text_input("Tempat, Tgl Lahir")
            gender = c1.selectbox("Jenis Kelamin", ["LAKI-LAKI", "PEREMPUAN"])
            alamat = c2.text_area("Alamat Lengkap")
            agama = c2.selectbox("Agama", ["ISLAM", "KRISTEN", "KATOLIK", "HINDU", "BUDDHA"])
            status = c2.selectbox("Status", ["BELUM KAWIN", "KAWIN", "CERAI"])
            pekerjaan = c2.text_input("Pekerjaan", "SWASTA")
            
            if st.button("ENKRIPSI & SIMPAN DATA"):
                if nik and nama:
                    data = {"NIK": nik, "Nama": nama.upper(), "TTL": ttl.upper(), "Gender": gender, "Alamat": alamat.upper(), "Agama": agama, "Status": status, "Pekerjaan": pekerjaan.upper()}
                    pkg, dbg = crypto.encrypt_hybrid(data, st.session_state['gen_pub'])
                    
                    fname = f"{nik}_{int(time.time())}.json"
                    with open(os.path.join(STORAGE_FOLDER, fname), 'w') as f: json.dump(pkg, f)
                    
                    st.success(f"DATA TERENKRIPSI! Disimpan sebagai: {fname}")
                    
                    with st.expander("🔍 LIHAT VISUALISASI BYTE (AES)"):
                        st.dataframe(create_df(dbg['sample_plain_bytes'], dbg['sample_cipher_bytes']), use_container_width=True)
                else:
                    st.warning("NIK dan Nama wajib diisi.")

# --- MENU 3 ---
elif menu == "3. DEKRIPSI DATA":
    st.subheader("Dekripsi Database (Scan)")
    st.markdown("<div class='info-box'>Unggah kunci privat (.pem) untuk membuka data yang terkunci.</div>", unsafe_allow_html=True)
    
    c1, c2 = st.columns(2)
    up_priv = c1.file_uploader("Upload Private Key", key="u_p")
    up_pub = c2.file_uploader("Upload Public Key", key="u_P")
    
    if st.button("SCAN & BUKA DATA"):
        if up_priv and up_pub:
            priv_obj, pub_obj = crypto.load_keys_from_pem(up_priv.getvalue(), up_pub.getvalue())
            if priv_obj:
                files = [f for f in os.listdir(STORAGE_FOLDER) if f.endswith('.json')]
                found = 0
                for fname in files:
                    try:
                        path = os.path.join(STORAGE_FOLDER, fname)
                        with open(path, 'r') as f: pkg = json.load(f)
                        res, smp_c, smp_p = crypto.decrypt_hybrid(pkg, priv_obj)
                        
                        if res:
                            found += 1
                            st.success(f"KUNCI COCOK: {fname}")
                            
                            ktp_html = textwrap.dedent(f"""
                                <div class="ktp-card">
                                    <div class="ktp-header">PROVINSI KALIMANTAN TIMUR<br>KOTA SAMARINDA</div>
                                    <div class="ktp-title">KARTU TANDA PENDUDUK</div>
                                    <div class="ktp-nik">{res.get('NIK','-')}</div>
                                    <div class="ktp-body">
                                        <div class="ktp-text">
                                            <table class="ktp-tabel">
                                                <tr><td class="lbl">Nama</td><td class="sep">:</td><td>{res.get('Nama','-')}</td></tr>
                                                <tr><td>Tempat/Tgl Lahir</td><td class="sep">:</td><td>{res.get('TTL','-')}</td></tr>
                                                <tr><td>Jenis Kelamin</td><td class="sep">:</td><td>{res.get('Gender','-')}</td></tr>
                                                <tr><td>Alamat</td><td class="sep">:</td><td>{res.get('Alamat','-')}</td></tr>
                                                <tr><td>   RT/RW</td><td class="sep">:</td><td>005/012</td></tr>
                                                <tr><td>   Kel/Desa</td><td class="sep">:</td><td>SIDOMULYO</td></tr>
                                                <tr><td>   Kecamatan</td><td class="sep">:</td><td>SAMARINDA ILIR</td></tr>
                                                <tr><td>Agama</td><td class="sep">:</td><td>{res.get('Agama','-')}</td></tr>
                                                <tr><td>Status</td><td class="sep">:</td><td>{res.get('Status','-')}</td></tr>
                                                <tr><td>Pekerjaan</td><td class="sep">:</td><td>{res.get('Pekerjaan','-')}</td></tr>
                                                <tr><td>Kewarganegaraan</td><td class="sep">:</td><td>WNI</td></tr>
                                                <tr><td>Berlaku Hingga</td><td class="sep">:</td><td>SEUMUR HIDUP</td></tr>
                                            </table>
                                        </div>
                                        <div class="ktp-photo-area">
                                            <div class="photo-box">FOTO</div>
                                            <div class="sign-box">
                                                Samarinda<br>24-11-2025<br><br><i>ttd</i><br><br>Kadisdukcapil
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            """)
                            st.markdown(ktp_html, unsafe_allow_html=True)
                            
                            with st.expander(f"DETAIL TEKNIS FILE: {fname}"):
                                st.write("Proses Pengembalian Data (AES-256 Decryption):")
                                st.dataframe(create_df(smp_p, smp_c, mode="decrypt"), use_container_width=True)
                    except: pass
                
                if found == 0: st.warning("Tidak ada data yang bisa dibuka dengan kunci ini.")
            else: st.error("Kunci rusak/tidak valid.")
        else: st.error("Harap upload kedua kunci.")