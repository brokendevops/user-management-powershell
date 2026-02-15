# Gelismis Kullanici Yonetim Scripti v2.0
# Yonetici olarak calistirilmali

# AD modulunu kontrol et
$ADAvailable = $false
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $ADAvailable = $true
    Write-Host "[OK] Active Directory modulu yuklendi" -ForegroundColor Green
} catch {
    Write-Host "[UYARI] Active Directory modulu bulunamadi - Sadece local kullanicilar yonetilebilir" -ForegroundColor Yellow
}

function Show-Menu {
    Clear-Host
    Write-Host "================ KULLANICI YONETIM SISTEMI v2.0 ================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "TEMEL ISLEMLER:" -ForegroundColor Yellow
    Write-Host "1:  Yeni Kullanici Olustur"
    Write-Host "2:  Kullanici Sil"
    Write-Host "3:  Tum Kullanicilari Listele"
    Write-Host "4:  Kullanici Bilgilerini Goruntule"
    Write-Host "5:  Toplu Kullanici Olustur (CSV'den)"
    Write-Host ""
    Write-Host "KULLANICI YONETIMI:" -ForegroundColor Yellow
    Write-Host "6:  Kullaniciyi Etkinlestir/Devre Disi Birak"
    Write-Host "7:  Sifre Sifirla"
    Write-Host ""
    Write-Host "GRUP YONETIMI:" -ForegroundColor Yellow
    Write-Host "8:  Kullaniciyi Gruba Ekle"
    Write-Host "9:  Kullaniciyi Gruptan Cikar"
    Write-Host "10: Kullanicinin Gruplarini Listele"
    Write-Host "11: Tum Gruplari Listele"
    Write-Host ""
    if ($ADAvailable) {
        Write-Host "ACTIVE DIRECTORY:" -ForegroundColor Yellow
        Write-Host "12: AD Kullanicisi Olustur"
        Write-Host "13: AD Kullanici Bilgileri"
        Write-Host "14: AD'den Kullanici Ara"
        Write-Host ""
    }
    Write-Host "MOD SECIMI:" -ForegroundColor Yellow
    Write-Host "M:  Mod Degistir (Local/AD) - Mevcut: $script:Mode"
    Write-Host "Q:  Cikis"
    Write-Host "================================================================" -ForegroundColor Cyan
}

# Global degisken - Local veya AD modu
$script:Mode = "Local"

function Switch-Mode {
    if ($ADAvailable) {
        if ($script:Mode -eq "Local") {
            $script:Mode = "AD"
            Write-Host "[OK] Active Directory moduna gecildi" -ForegroundColor Green
        } else {
            $script:Mode = "Local"
            Write-Host "[OK] Local kullanici moduna gecildi" -ForegroundColor Green
        }
    } else {
        Write-Host "[HATA] Active Directory modulu mevcut degil!" -ForegroundColor Red
    }
    Start-Sleep -Seconds 1
}

function Write-Log {
    param($Message)
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - [$script:Mode] - $Message"
    Add-Content -Path "C:\UserManagement_Log.txt" -Value $logEntry
}

function Create-NewUser {
    Write-Host "`n--- Yeni Kullanici Olustur ($script:Mode) ---" -ForegroundColor Green
    
    $username = Read-Host "Kullanici adi"
    $fullname = Read-Host "Tam adi"
    $description = Read-Host "Aciklama"
    $password = Read-Host "Sifre" -AsSecureString
    
    try {
        if ($script:Mode -eq "Local") {
            New-LocalUser -Name $username -Password $password -FullName $fullname -Description $description -ErrorAction Stop
            
            Write-Host "[OK] Local kullanici basariyla olusturuldu: $username" -ForegroundColor Green
        } else {
            # AD kullanicisi olustur
            $ou = Read-Host "OU yolu (orn: OU=Users,DC=domain,DC=com)"
            
            New-ADUser -Name $username -GivenName ($fullname.Split(' ')[0]) -Surname ($fullname.Split(' ')[-1]) -SamAccountName $username -UserPrincipalName "$username@$env:USERDNSDOMAIN" -Path $ou -AccountPassword $password -Description $description -Enabled $true -ErrorAction Stop
            
            Write-Host "[OK] AD kullanicisi basariyla olusturuldu: $username" -ForegroundColor Green
        }
        
        Write-Log "OLUSTURMA - $username - $fullname"
        
    } catch {
        Write-Host "[HATA] $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Read-Host "`nDevam etmek icin Enter'a basin"
}

function Remove-UserAccount {
    Write-Host "`n--- Kullanici Sil ($script:Mode) ---" -ForegroundColor Red
    
    $username = Read-Host "Silinecek kullanici adi"
    
    try {
        if ($script:Mode -eq "Local") {
            $user = Get-LocalUser -Name $username -ErrorAction Stop
            Write-Host "`nKullanici: $($user.Name) - $($user.FullName)"
        } else {
            $user = Get-ADUser -Identity $username -Properties * -ErrorAction Stop
            Write-Host "`nKullanici: $($user.SamAccountName) - $($user.Name)"
        }
        
        $confirmation = Read-Host "`nBu kullaniciyi silmek istediginize emin misiniz? (E/H)"
        
        if ($confirmation -eq 'E') {
            if ($script:Mode -eq "Local") {
                Remove-LocalUser -Name $username
            } else {
                Remove-ADUser -Identity $username -Confirm:$false
            }
            
            Write-Host "[OK] Kullanici silindi: $username" -ForegroundColor Green
            Write-Log "SILME - $username"
        } else {
            Write-Host "Islem iptal edildi." -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "[HATA] Kullanici bulunamadi: $username" -ForegroundColor Red
    }
    
    Read-Host "`nDevam etmek icin Enter'a basin"
}

function Show-AllUsers {
    Write-Host "`n--- Tum Kullanicilar ($script:Mode) ---" -ForegroundColor Cyan
    
    if ($script:Mode -eq "Local") {
        Get-LocalUser | Format-Table Name, FullName, Enabled, LastLogon -AutoSize
    } else {
        Get-ADUser -Filter * -Properties LastLogonDate | Format-Table SamAccountName, Name, Enabled, LastLogonDate -AutoSize
    }
    
    Read-Host "`nDevam etmek icin Enter'a basin"
}

function Show-UserInfo {
    Write-Host "`n--- Kullanici Bilgileri ($script:Mode) ---" -ForegroundColor Cyan
    
    $username = Read-Host "Kullanici adi"
    
    try {
        if ($script:Mode -eq "Local") {
            $user = Get-LocalUser -Name $username -ErrorAction Stop
            
            Write-Host "`nKullanici Detaylari:" -ForegroundColor Green
            Write-Host "Ad: $($user.Name)"
            Write-Host "Tam Ad: $($user.FullName)"
            Write-Host "Aciklama: $($user.Description)"
            Write-Host "Aktif: $($user.Enabled)"
            Write-Host "Son Giris: $($user.LastLogon)"
            Write-Host "Sifre Suresi Doldu: $($user.PasswordExpired)"
            
        } else {
            $user = Get-ADUser -Identity $username -Properties * -ErrorAction Stop
            
            Write-Host "`nKullanici Detaylari:" -ForegroundColor Green
            Write-Host "AD Adi: $($user.SamAccountName)"
            Write-Host "Tam Ad: $($user.Name)"
            Write-Host "Email: $($user.EmailAddress)"
            Write-Host "Departman: $($user.Department)"
            Write-Host "Unvan: $($user.Title)"
            Write-Host "Aktif: $($user.Enabled)"
            Write-Host "Son Giris: $($user.LastLogonDate)"
            Write-Host "OU: $($user.DistinguishedName)"
        }
        
    } catch {
        Write-Host "[HATA] Kullanici bulunamadi: $username" -ForegroundColor Red
    }
    
    Read-Host "`nDevam etmek icin Enter'a basin"
}

function Enable-DisableUser {
    Write-Host "`n--- Kullaniciyi Etkinlestir/Devre Disi Birak ($script:Mode) ---" -ForegroundColor Cyan
    
    $username = Read-Host "Kullanici adi"
    
    try {
        if ($script:Mode -eq "Local") {
            $user = Get-LocalUser -Name $username -ErrorAction Stop
            
            Write-Host "`nMevcut Durum: $($user.Enabled)"
            Write-Host "1: Etkinlestir"
            Write-Host "2: Devre Disi Birak"
            $choice = Read-Host "Seciminiz"
            
            if ($choice -eq "1") {
                Enable-LocalUser -Name $username
                Write-Host "[OK] Kullanici etkinlestirildi" -ForegroundColor Green
                Write-Log "ETKINLESTIRME - $username"
            } elseif ($choice -eq "2") {
                Disable-LocalUser -Name $username
                Write-Host "[OK] Kullanici devre disi birakildi" -ForegroundColor Yellow
                Write-Log "DEVRE DISI - $username"
            }
            
        } else {
            $user = Get-ADUser -Identity $username -ErrorAction Stop
            
            Write-Host "`nMevcut Durum: $($user.Enabled)"
            Write-Host "1: Etkinlestir"
            Write-Host "2: Devre Disi Birak"
            $choice = Read-Host "Seciminiz"
            
            if ($choice -eq "1") {
                Enable-ADAccount -Identity $username
                Write-Host "[OK] Kullanici etkinlestirildi" -ForegroundColor Green
                Write-Log "ETKINLESTIRME - $username"
            } elseif ($choice -eq "2") {
                Disable-ADAccount -Identity $username
                Write-Host "[OK] Kullanici devre disi birakildi" -ForegroundColor Yellow
                Write-Log "DEVRE DISI - $username"
            }
        }
        
    } catch {
        Write-Host "[HATA] $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Read-Host "`nDevam etmek icin Enter'a basin"
}

function Reset-UserPassword {
    Write-Host "`n--- Sifre Sifirla ($script:Mode) ---" -ForegroundColor Cyan
    
    $username = Read-Host "Kullanici adi"
    $newPassword = Read-Host "Yeni sifre" -AsSecureString
    
    try {
        if ($script:Mode -eq "Local") {
            $user = Get-LocalUser -Name $username -ErrorAction Stop
            $user | Set-LocalUser -Password $newPassword
            
            Write-Host "[OK] Sifre basariyla sifirlandi" -ForegroundColor Green
            
        } else {
            Set-ADAccountPassword -Identity $username -NewPassword $newPassword -Reset
            
            $changeAtLogon = Read-Host "Ilk giriste sifre degistirsin mi? (E/H)"
            if ($changeAtLogon -eq "E") {
                Set-ADUser -Identity $username -ChangePasswordAtLogon $true
            }
            
            Write-Host "[OK] Sifre basariyla sifirlandi" -ForegroundColor Green
        }
        
        Write-Log "SIFRE SIFIRLAMA - $username"
        
    } catch {
        Write-Host "[HATA] $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Read-Host "`nDevam etmek icin Enter'a basin"
}

function Add-UserToGroup {
    Write-Host "`n--- Kullaniciyi Gruba Ekle ($script:Mode) ---" -ForegroundColor Green
    
    $username = Read-Host "Kullanici adi"
    
    try {
        if ($script:Mode -eq "Local") {
            # Local gruplari listele
            Write-Host "`nMevcut Gruplar:" -ForegroundColor Yellow
            Get-LocalGroup | Format-Table Name, Description
            
            $groupName = Read-Host "`nGrup adi"
            
            Add-LocalGroupMember -Group $groupName -Member $username
            Write-Host "[OK] Kullanici gruba eklendi: $username -> $groupName" -ForegroundColor Green
            
        } else {
            # AD gruplarini listele
            Write-Host "`nGrup aramak icin anahtar kelime girin (bos birakirsaniz tumu listelenir):"
            $searchTerm = Read-Host "Arama"
            
            if ($searchTerm) {
                Get-ADGroup -Filter "Name -like '*$searchTerm*'" | Format-Table Name, GroupScope
            } else {
                Get-ADGroup -Filter * | Select-Object -First 20 | Format-Table Name, GroupScope
            }
            
            $groupName = Read-Host "`nGrup adi"
            
            Add-ADGroupMember -Identity $groupName -Members $username
            Write-Host "[OK] Kullanici gruba eklendi: $username -> $groupName" -ForegroundColor Green
        }
        
        Write-Log "GRUBA EKLEME - $username -> $groupName"
        
    } catch {
        Write-Host "[HATA] $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Read-Host "`nDevam etmek icin Enter'a basin"
}

function Remove-UserFromGroup {
    Write-Host "`n--- Kullaniciyi Gruptan Cikar ($script:Mode) ---" -ForegroundColor Red
    
    $username = Read-Host "Kullanici adi"
    
    try {
        # Once kullanicinin gruplarini goster
        Write-Host "`n$username kullanicisinin gruplari:" -ForegroundColor Yellow
        
        if ($script:Mode -eq "Local") {
            Get-LocalGroup | ForEach-Object {
                $group = $_
                $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
                if ($members.Name -contains "$env:COMPUTERNAME\$username") {
                    Write-Host "- $($group.Name)"
                }
            }
            
            $groupName = Read-Host "`nCikarilacak grup adi"
            Remove-LocalGroupMember -Group $groupName -Member $username
            
        } else {
            Get-ADUser -Identity $username -Properties MemberOf | Select-Object -ExpandProperty MemberOf | ForEach-Object { $_ -replace '^CN=([^,]+).*','$1' }
            
            $groupName = Read-Host "`nCikarilacak grup adi"
            Remove-ADGroupMember -Identity $groupName -Members $username -Confirm:$false
        }
        
        Write-Host "[OK] Kullanici gruptan cikarildi: $username <- $groupName" -ForegroundColor Green
        Write-Log "GRUPTAN CIKARMA - $username <- $groupName"
        
    } catch {
        Write-Host "[HATA] $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Read-Host "`nDevam etmek icin Enter'a basin"
}

function Show-UserGroups {
    Write-Host "`n--- Kullanicinin Gruplari ($script:Mode) ---" -ForegroundColor Cyan
    
    $username = Read-Host "Kullanici adi"
    
    try {
        Write-Host "`n$username kullanicisinin gruplari:" -ForegroundColor Green
        
        if ($script:Mode -eq "Local") {
            Get-LocalGroup | ForEach-Object {
                $group = $_
                $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
                if ($members.Name -contains "$env:COMPUTERNAME\$username") {
                    Write-Host "[+] $($group.Name) - $($group.Description)" -ForegroundColor Yellow
                }
            }
        } else {
            Get-ADUser -Identity $username -Properties MemberOf | Select-Object -ExpandProperty MemberOf | ForEach-Object {
                $groupDN = $_
                $groupName = $_ -replace '^CN=([^,]+).*','$1'
                Write-Host "[+] $groupName" -ForegroundColor Yellow
            }
        }
        
    } catch {
        Write-Host "[HATA] $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Read-Host "`nDevam etmek icin Enter'a basin"
}

function Show-AllGroups {
    Write-Host "`n--- Tum Gruplar ($script:Mode) ---" -ForegroundColor Cyan
    
    if ($script:Mode -eq "Local") {
        Get-LocalGroup | Format-Table Name, Description -AutoSize
    } else {
        Write-Host "Ilk 50 grup gosteriliyor..."
        Get-ADGroup -Filter * | Select-Object -First 50 | Format-Table Name, GroupScope, GroupCategory -AutoSize
    }
    
    Read-Host "`nDevam etmek icin Enter'a basin"
}

function Search-ADUsers {
    if ($script:Mode -ne "AD") {
        Write-Host "[HATA] Bu ozellik sadece AD modunda calisir" -ForegroundColor Red
        Read-Host "`nDevam etmek icin Enter'a basin"
        return
    }
    
    Write-Host "`n--- AD'den Kullanici Ara ---" -ForegroundColor Cyan
    
    $searchTerm = Read-Host "Arama terimi (ad, soyad veya kullanici adi)"
    
    try {
        $users = Get-ADUser -Filter "Name -like '*$searchTerm*' -or SamAccountName -like '*$searchTerm*'" -Properties Department, Title
        
        if ($users) {
            Write-Host "`nBulunan kullanicilar:" -ForegroundColor Green
            $users | Format-Table SamAccountName, Name, Department, Title -AutoSize
        } else {
            Write-Host "[HATA] Kullanici bulunamadi" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "[HATA] $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Read-Host "`nDevam etmek icin Enter'a basin"
}

function Import-UsersFromCSV {
    Write-Host "`n--- CSV'den Toplu Kullanici Olustur ($script:Mode) ---" -ForegroundColor Green
    
    $csvPath = Read-Host "CSV dosya yolu"
    
    if (Test-Path $csvPath) {
        $users = Import-Csv $csvPath
        $successCount = 0
        $failCount = 0
        
        foreach ($user in $users) {
            try {
                $password = ConvertTo-SecureString $user.Password -AsPlainText -Force
                
                if ($script:Mode -eq "Local") {
                    New-LocalUser -Name $user.Username -Password $password -FullName $user.FullName -Description $user.Description -ErrorAction Stop
                } else {
                    New-ADUser -Name $user.Username -SamAccountName $user.Username -UserPrincipalName "$($user.Username)@$env:USERDNSDOMAIN" -GivenName ($user.FullName.Split(' ')[0]) -Surname ($user.FullName.Split(' ')[-1]) -AccountPassword $password -Description $user.Description -Enabled $true -ErrorAction Stop
                }
                
                Write-Host "[OK] Olusturuldu: $($user.Username)" -ForegroundColor Green
                $successCount++
                Write-Log "TOPLU OLUSTURMA - $($user.Username)"
                
            } catch {
                Write-Host "[HATA] ($($user.Username)): $($_.Exception.Message)" -ForegroundColor Red
                $failCount++
            }
        }
        
        Write-Host "`n--- Ozet ---" -ForegroundColor Cyan
        Write-Host "Basarili: $successCount" -ForegroundColor Green
        Write-Host "Basarisiz: $failCount" -ForegroundColor Red
        
    } else {
        Write-Host "[HATA] CSV dosyasi bulunamadi!" -ForegroundColor Red
    }
    
    Read-Host "`nDevam etmek icin Enter'a basin"
}

# Ana Program Dongusu
do {
    Show-Menu
    $selection = Read-Host "`nSeciminiz"
    
    switch ($selection) {
        '1'  { Create-NewUser }
        '2'  { Remove-UserAccount }
        '3'  { Show-AllUsers }
        '4'  { Show-UserInfo }
        '5'  { Import-UsersFromCSV }
        '6'  { Enable-DisableUser }
        '7'  { Reset-UserPassword }
        '8'  { Add-UserToGroup }
        '9'  { Remove-UserFromGroup }
        '10' { Show-UserGroups }
        '11' { Show-AllGroups }
        '12' { Create-NewUser }
        '13' { Show-UserInfo }
        '14' { Search-ADUsers }
        'M'  { Switch-Mode }
    }
} until ($selection -eq 'Q')

Write-Host "`nProgram sonlandirildi. Iyi gunler!" -ForegroundColor Cyan