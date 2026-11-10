# Atarenver Gate (Render)

Gate ini menjadi domain publik untuk klien VPN sekaligus generator akun VLESS. Semua koneksi WebSocket diteruskan ke satu backend ServerVPN di Vercel.

## Konfigurasi default

| Environment | Nilai |
|---|---|
| `SERVERVPN_ORIGIN` | `https://atavpnvercel.vercel.app` |
| `VPN_UUID` | `d1cf4b9c-3e57-085d-b34a-797fcf601381` |
| `VPN_WS_PATH` | `/d1cf4b9c` |
| `PORT` | Disediakan Render (Docker default 10000) |
| `DEFAULT_ADMIN_PASSWORD` | Wajib diatur sendiri di Render |
| `SESSION_SECRET` | Dibuat otomatis oleh `render.yaml` atau diatur manual |

UUID dan path harus sama dengan `UUID` dan `WSPATH` di ServerVPN. Pada script ServerVPN yang diberikan, nilai default keduanya memang cocok: UUID `d1cf4b9c-3e57-085d-b34a-797fcf601381` dan path `/d1cf4b9c`.

## Deploy ke Render

1. Push isi folder ini ke repository GitHub.
2. Di Render pilih **New > Blueprint** bila menggunakan `render.yaml`, atau **New > Web Service** dan pilih runtime Docker.
3. Gunakan nama service `atarenver`. Domain publik akan diberikan oleh Render; generator membaca hostname dari request sehingga tidak perlu menuliskan domain Render secara manual.
4. Isi `DEFAULT_ADMIN_PASSWORD` dengan password admin yang kuat. `SESSION_SECRET` dibuat otomatis melalui Blueprint.
5. Pastikan health check menggunakan `/health`.

## Endpoint

- `/` — halaman status Gate.
- `/sub` — halaman generator VLESS.
- `/sub.txt` — satu baris URI VLESS plain text.
- `/health` — status proses Gate dan target backend yang dikunci.
- `/admin` — pemeriksaan backend dan penggantian password admin.

## Alur koneksi

Klien terhubung ke `wss://<domain-render>/d1cf4b9c`. Gate menerima TLS dari Render, lalu membuat koneksi `wss://atavpnvercel.vercel.app/d1cf4b9c` dan meneruskan frame WebSocket dua arah. Gate tidak lagi mengunduh daftar Proxy Bank, tidak lagi memakai alamat IP:port sebagai path, dan tidak membuat UUID acak.

Catatan: keberhasilan deploy domain Vercel saja belum membuktikan WebSocket ServerVPN bisa menerima koneksi. Uji langsung endpoint Vercel dan pastikan project ServerVPN diekspor sebagai Vercel Function/WebSocket handler sesuai runtime Vercel yang digunakan.

## Catatan kompatibilitas ServerVPN di Vercel

File ServerVPN yang disertakan saat analisis membuat `httpServer` dan memanggil `httpServer.listen(PORT)` di bagian akhir, tetapi tidak mengekspor objek server sebagai entrypoint Function. Pola WebSocket Vercel yang didokumentasikan adalah membuat HTTP server, memasang `WebSocketServer`, lalu mengekspor server tersebut dari entrypoint Function. Jadi, periksa adapter/export ServerVPN sebelum menganggap koneksi Gate sudah dapat diteruskan.

Selain itu, `vercel.json` ServerVPN yang dikirim menetapkan `maxDuration: 300`. Vercel menutup koneksi WebSocket ketika Function mencapai batas durasi; 300 detik berarti koneksi dapat terputus setelah sekitar 5 menit. Gate tidak dapat mempertahankan sesi TCP VPN yang sudah putus hanya dengan menyambungkan ulang WebSocket upstream.
