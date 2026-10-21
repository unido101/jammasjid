# Jam Digital Masjid Raya Al-Falah Sragen

Web app satu halaman untuk layar masjid dan Android TV. Tidak memerlukan instalasi paket atau proses build.

## Menjalankan

Untuk mencoba, buka `index.html` di browser komputer. Untuk dipakai di Android TV, unggah `index.html` dan `alarm-clock-sound-effects-07.wav` bersama-sama ke hosting web statis agar mendapat alamat HTTPS. Setelah itu:

1. Sambungkan TV ke internet dan buka alamat HTTPS tersebut di browser TV.
2. Pilih **Tampilkan fullscreen** pada ikon ⚙. Jika perlu, tekan tombol `F` dengan keyboard; `Escape` untuk keluar.
3. Simpan alamat halaman sebagai bookmark. Atur browser agar memulihkan tab terakhir saat TV/browser dibuka kembali.
4. Untuk pengoperasian khusus layar masjid, aktifkan mode kiosk/browser fullscreen pada TV atau browser jika tersedia.

## Isi layar

- Jam digital, tanggal Masehi dan Hijriah.
- Jadwal Subuh, Zuhur, Asar, Magrib, dan Isya dari AlAdhan dengan metode Kemenag RI (metode 20).
- Hitung mundur menuju adzan, lalu countdown jeda iqomah untuk salat yang sedang berlangsung.
- File `alarm-clock-sound-effects-07.wav` diputar saat hitung mundur iqomah selesai. Tekan **Aktifkan & tes suara** sekali di menu pengaturan setelah membuka halaman agar browser TV mengizinkan audio.
- Setelah iqomah, layar menjadi hitam dengan jam kecil putih di tengah. Durasi layar gelap dapat diatur satu per satu untuk Subuh, Zuhur, Asar, Magrib, dan Isya; isi 0 untuk mematikannya.
- Koreksi waktu, jeda iqomah, dan durasi layar gelap dapat diatur per salat. Pengaturan tersimpan di browser/perangkat yang digunakan.
- Jadwal tersimpan sebagai cadangan bila koneksi terputus.

Buka ikon ⚙ untuk pengaturan. Cocokkan jadwal dengan jadwal resmi yang digunakan takmir sebelum layar dipakai untuk memandu jamaah. Bunyi otomatis bergantung pada izin audio browser dan volume TV.

## Catatan

Jadwal awal memakai koordinat perkiraan pusat Sragen (`-7.4297, 111.0215`), bukan hasil survei titik masjid. Sesuaikan koordinat dan koreksi berdasarkan jadwal resmi Masjid Raya Al-Falah. Data waktu awal dihitung melalui API AlAdhan; browser perlu internet untuk mengambil jadwal harian pertama kali. Jam perangkat TV sebaiknya diatur ke zona waktu Jakarta (WIB) dan disinkronkan otomatis.
