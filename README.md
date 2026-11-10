# Atarenver Gate 2.1 — Render Multi-Protocol + Automatic Failover

Gate ini menjadi domain publik klien VPN. Klien selalu terhubung ke domain Render; Gate meneruskan koneksi WebSocket ke backend yang tersedia dengan urutan **Vercel utama → 3 backend Wasmer cadangan**.

## Backend default

| Prioritas | Backend | Peran |
|---:|---|---|
| 1 | `atavpnvercel.vercel.app` | Primary — Vercel |
| 2 | `atawsn.wasmer.app` | Fallback 1 — Wasmer |
| 3 | `atapyv.wasmer.app` | Fallback 2 — Wasmer |
| 4 | `node-base-ad688.wasmer.app` | Fallback 3 — Wasmer |

Gate mencoba Vercel terlebih dahulu. Jika koneksi WebSocket ditolak, timeout, gagal jaringan, menerima HTTP 429 (rate limit), atau 5xx, backend tersebut dimasukkan cooldown 90 detik dan Gate mencoba backend berikutnya. Backend yang berhasil akan dipakai. HTTP forwarding juga berpindah backend untuk 408, 425, 429, 5xx dan error jaringan.

Pada koneksi yang sudah aktif, Gate tidak dapat memindahkan stream TCP/VPN yang sedang berjalan ke backend lain tanpa memutus sesi karena status koneksi sudah berada di backend lama. Jika upstream memutus WebSocket secara abnormal, Gate menandai backend tersebut cooldown dan menutup koneksi klien dengan kode reconnect; koneksi klien berikutnya akan memilih backend cadangan. Jadi failover terjadi saat handshake/koneksi baru, bukan migrasi sesi aktif tanpa putus.

## Protokol dan autentikasi

Gate mengeluarkan tiga format akun dari generator:

- **VLESS** — UUID ServerVPN sebagai ID.
- **Trojan** — UUID ServerVPN sebagai password Trojan.
- **Shadowsocks** — metode `none`, password UUID, transport `v2ray-plugin` melalui WebSocket TLS.

Ketiganya memakai hostname publik Render, port `443`, TLS, WebSocket path `/d1cf4b9c`, dan host/SNI domain Render. Ini mengikuti `index.js` ServerVPN yang disertakan: server mengenali VLESS, Trojan, dan Shadowsocks pada WebSocket path yang sama. Pastikan ketiga Wasmer backend juga menjalankan konfigurasi UUID dan WSPATH yang sama.

Default credential/path:

| Environment | Nilai |
|---|---|
| `SERVERVPN_ORIGIN` | `https://atavpnvercel.vercel.app` |
| `FALLBACK_BACKENDS` | `atawsn.wasmer.app,atapyv.wasmer.app,node-base-ad688.wasmer.app` |
| `VPN_UUID` | `d1cf4b9c-3e57-085d-b34a-797fcf601381` |
| `VPN_WS_PATH` | `/d1cf4b9c` |
| `PORT` | Diisi Render (default Docker `10000`) |
| `DEFAULT_ADMIN_PASSWORD` | Atur password admin kuat di Render |
| `SESSION_SECRET` | Dibuat otomatis oleh Blueprint atau atur sendiri |

`FALLBACK_BACKENDS` bisa diisi hostname dipisahkan koma. Semua backend wajib memakai HTTPS/WSS dan path/UUID yang sama. Urutan nilai menentukan prioritas.

## Deploy ke Render

1. Push isi folder ZIP ini ke repository GitHub.
2. Di Render pilih **New → Blueprint** untuk memakai `render.yaml`, atau buat Web Service dengan runtime Docker.
3. Nama service: `atarenver`. Domain publik akan diberikan Render; generator otomatis memakai hostname dari request klien.
4. Isi `DEFAULT_ADMIN_PASSWORD` dan `SESSION_SECRET` sesuai kebutuhan. Jangan memakai password default.
5. Health check path: `/health`.

## Endpoint

- `/` — status Gate.
- `/sub` — generator visual, tombol salin untuk tiga protokol.
- `/sub.txt` — subscription Base64 berisi tiga URI (VLESS, Trojan, SS).
- `/sub.raw` — tiga URI dalam teks biasa.
- `/sub.vless` — URI VLESS saja.
- `/sub.trojan` — URI Trojan saja.
- `/sub.ss` — URI Shadowsocks saja.
- `/health` — status Gate dan urutan backend/cooldown.
- `/admin` — panel admin, ubah password dan periksa semua backend.

## Cara kerja failover

1. Klien membuka TLS ke domain Render dan upgrade WebSocket pada `/d1cf4b9c`.
2. Gate mencoba `wss://atavpnvercel.vercel.app/d1cf4b9c`.
3. Jika handshake sukses, Gate meneruskan frame dua arah melalui Vercel.
4. Jika Vercel merespons 429/5xx, handshake gagal, timeout, atau error jaringan, Gate mencoba `atawsn.wasmer.app`, kemudian `atapyv.wasmer.app`, lalu `node-base-ad688.wasmer.app`.
5. Backend yang gagal dihindari selama 90 detik. Setelah cooldown berakhir, Gate mencoba lagi sesuai urutan prioritas.
6. Jika upstream aktif putus abnormal (misalnya batas durasi Function), backend itu dimasukkan cooldown. Klien perlu reconnect agar pindah ke backend cadangan.

Panel `/admin` menyediakan tombol **CHECK ALL UPSTREAMS** untuk pemeriksaan HTTP root masing-masing backend. Pemeriksaan ini hanya mengecek akses root; uji paling relevan untuk tunneling tetap koneksi WebSocket dari aplikasi VPN.

## Catatan

- Semua backend Wasmer wajib menjalankan ServerVPN yang kompatibel, bukan hanya halaman placeholder. UUID dan path harus identik.
- Shadowsocks memerlukan klien yang mendukung plugin `v2ray-plugin` dengan mode WebSocket TLS.
- Failover otomatis tidak dapat memindahkan sesi yang sedang aktif tanpa reconnect klien.
- Jika Vercel mencapai batas durasi Function dan memutus WebSocket, Gate dapat mengarahkan **koneksi ulang** ke Wasmer. Gate tidak dapat memperpanjang durasi Function Vercel.
