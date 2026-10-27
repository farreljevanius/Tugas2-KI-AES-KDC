# Tugas 2 Keamanan Informasi: KDC dan AES Manual

Proyek ini mengimplementasikan distribusi session key melalui Key Distribution Center (KDC) dan komunikasi dua arah antara Alice dan Bob menggunakan AES manual.

## Anggota Kelompok

**Kelompok A11**

| Nama | NRP |
|---|---|
| Farrel Jevanius Tjandra | 5025241259 |
| Herdian Tri Wardhana | 5025241229 |

## Penjelasan File

### 1. aes.py

Berisi implementasi AES-128, AES-192, dan AES-256 tanpa library kriptografi siap pakai.

Bagian utama:

- Perhitungan pada GF(2⁸) dan pembentukan S-box beserta inversnya.
- Key expansion untuk menghasilkan round key.
- Operasi SubBytes, ShiftRows, MixColumns, dan AddRoundKey.
- Operasi invers untuk dekripsi.
- Mode CBC dengan IV acak dan padding PKCS#7.
- Validasi key ASCII serta konversi plaintext ASCII dan ciphertext Hex.
- Self-test menggunakan vektor AES dan pengujian round-trip CBC.

Kelas `AES` menangani enkripsi dan dekripsi satu blok. Fungsi `encrypt_text()` dan `decrypt_text()` menjadi penghubung antara algoritma tersebut dan data teks yang digunakan program KDC maupun node.

### 2. proto.py

Berisi fungsi pendukung komunikasi melalui socket TCP.

Data dikemas sebagai array JSON ASCII, dengan satu baris untuk setiap pesan. Format ini menjaga agar karakter seperti pipe, kutip, dan backslash di dalam field tetap dapat dibaca dengan benar.

Bagian utama:

- `pack_fields()`: mengemas field menjadi JSON ASCII.
- `unpack_fields()`: membaca dan memvalidasi field JSON.
- `Channel`: mengirim, menerima, dan menutup koneksi.
- `dial()`: membuat koneksi TCP ke alamat tujuan.
- `listen()`: membuat socket yang menerima koneksi.
- `split_address()`: memisahkan alamat IP dan port.

`Channel` menggunakan lock saat mengirim agar pengiriman bersamaan tidak mencampur data pesan.

### 3. kdc.py

Berisi server KDC yang menyimpan master key untuk setiap identitas dan membagikan session key kepada pihak yang akan berkomunikasi.

Tanggung jawabnya:

- Menyimpan master key Alice dan Bob dalam memori.
- Menerima permintaan berisi ID_A, ID_B, dan nonce N1.
- Membentuk session key Ks berupa teks ASCII.
- Membuat reply untuk Alice yang dienkripsi menggunakan Ka.
- Membuat ticket untuk Bob yang dienkripsi menggunakan Kb.
- Mengirim reply dan ticket sebagai dua bagian terpisah sesuai langkah kedua skenario.
- Menyediakan perintah interaktif untuk mengganti master key dan memilih session key acak atau manual.

KDC menggunakan `aes.py` untuk enkripsi dan `proto.py` untuk komunikasi TCP.

### 4. node.py

Berisi program peer yang dapat dijalankan sebagai Alice atau Bob. Setiap node dapat menjadi initiator maupun responder.

Tanggung jawabnya:

- Meminta session key kepada KDC.
- Memeriksa ID_A, ID_B, dan N1 pada reply KDC.
- Meneruskan ticket kepada peer tujuan.
- Mengirim dan memverifikasi challenge-response menggunakan N2 dan `f(N2) = N2 - 1`.
- Membuka sesi setelah verifikasi langkah kelima dan konfirmasi `READY`.
- Mengirim dan menerima pesan menggunakan session key yang sama.
- Menampilkan plaintext ASCII dan ciphertext Hex.
- Menyediakan perintah untuk melihat status, mengganti master key, dan menutup sesi.

Penerimaan pesan berjalan pada thread terpisah sehingga node tetap dapat mengirim pesan ketika sedang menunggu pesan masuk.
