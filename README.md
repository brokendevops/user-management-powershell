# Windows User Management Script

PowerShell tabanlı kullanıcı yönetim aracı. Local kullanıcılar ve Active Directory kullanıcıları için kapsamlı yönetim özellikleri sunar.

## Özellikler

### Temel İşlemler
- ✅ Yeni kullanıcı oluşturma
- ✅ Kullanıcı silme
- ✅ Kullanıcı listeleme
- ✅ Kullanıcı bilgilerini görüntüleme
- ✅ CSV dosyasından toplu kullanıcı oluşturma

### Kullanıcı Yönetimi
- 🔐 Şifre sıfırlama
- 🔄 Kullanıcı etkinleştirme/devre dışı bırakma

### Grup Yönetimi
- 👥 Kullanıcıyı gruba ekleme
- ➖ Kullanıcıyı gruptan çıkarma
- 📋 Kullanıcının gruplarını listeleme
- 📊 Tüm grupları listeleme

### Active Directory Desteği
- 🌐 AD kullanıcısı oluşturma
- 🔍 AD'den kullanıcı arama
- 📁 OU bazlı yönetim

## Gereksinimler

- Windows 10/11 veya Windows Server 2016+
- PowerShell 5.1 veya üzeri
- Yönetici (Administrator) yetkileri
- Active Directory özellikler için: RSAT (Remote Server Administration Tools)

## Kurulum

1. Projeyi indirin veya klonlayın
2. PowerShell'i **yönetici olarak** çalıştırın
3. Script'in bulunduğu klasöre gidin
4. Execution Policy ayarlayın:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Kullanım
```powershell
.\UserManagement.ps1
```

Script başladığında interaktif menü görünecektir. Yapmak istediğiniz işlemi seçin.

### Örnek: Yeni Kullanıcı Oluşturma

1. Menüden `1` seçin
2. Kullanıcı adı girin
3. Tam ad girin
4. Açıklama girin
5. Şifre girin

### Örnek: CSV'den Toplu Kullanıcı Oluşturma

CSV dosyası formatı:
```csv
Username,FullName,Description,Password
mehmet.kaya,Mehmet Kaya,Muhasebe Departmani,Sifre123!
ayse.demir,Ayse Demir,Insan Kaynaklari,Sifre456!
```

Menüden `5` seçin ve CSV dosya yolunu girin.

## Mod Değiştirme

Script iki modda çalışır:
- **Local Mod**: Bilgisayarınızdaki yerel kullanıcıları yönetir
- **AD Mod**: Active Directory kullanıcılarını yönetir (RSAT gerektirir)

Menüden `M` tuşuna basarak mod değiştirebilirsiniz.

## Loglama

Tüm işlemler `C:\UserManagement_Log.txt` dosyasına kaydedilir.

Format:
```
2026-02-09 14:23:15 - [Local] - OLUSTURMA - test.user - Test User
2026-02-09 14:25:30 - [Local] - SILME - test.user
```

## Güvenlik Notları

⚠️ **Önemli:**
- Script'i sadece yönetici olarak çalıştırın
- Güçlü şifreler kullanın
- Üretim ortamında kullanmadan önce test edin
- Log dosyalarını düzenli kontrol edin

## Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/YeniOzellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'Yeni özellik eklendi'`)
4. Branch'i push edin (`git push origin feature/YeniOzellik`)
5. Pull Request açın

## Yapılacaklar (Roadmap)

- [ ] GUI arayüz eklenmesi
- [ ] Email bildirimleri
- [ ] Excel rapor oluşturma
- [ ] Çoklu dil desteği
- [ ] Yedekleme/geri yükleme özelliği

## Lisans

MIT License - detaylar için `LICENSE` dosyasına bakın.

## İletişim

Sorularınız veya önerileriniz için Issue açabilirsiniz.

---

**Not:** Bu proje eğitim ve IT destek amaçlı geliştirilmiştir. Üretim ortamında kullanmadan önce testlerinizi yapın.
```
