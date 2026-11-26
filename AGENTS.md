# VirusTotalScanner — Proje Hafızası

## Dağıtım ve Yayınlama

- Bu projede yerel dağıtım ve varsayılan yayın çıktısı **her zaman self-contained** (`--self-contained true -p:PublishSingleFile=true -p:PublishReadyToRun=true`, `publish\portable\VirusTotalScanner.exe`) tek EXE olarak üretilir; yerel kurulumda (`C:\E\kp\aaBenimProgramlarim\VirusTotalScanner\VirusTotalScanner.exe`) framework-dependent çıktı kullanılmaz. Ayrıntı: [docs/guncelleme.md](docs/guncelleme.md).

## Dokümantasyon

İşe başlamadan önce [dokümantasyon rehberini](docs/Dokümantasyon-Nasıl-Yapılır.md) ve [giriş fihristini](docs/İçindekiler.md) oku; görevle ilgili belgelere fihristten ilerle. Projede emekle öğrenilen, tekrar kullanılabilir ve doğrulanmış bilgiyi işin parçası olarak belgele; eskiyen bilgiyi ve ilgili fihristleri kullanıcı ayrıca istemeden güncelle. Genel internet bilgisini, geçici durumları ve yapılan işlerin günlüğünü `docs/` altına taşıma.

## Walkthrough

Projeyi devralırken [Walkthrough rehberini](Walkthrough/Walkthrough-Rehberi.md) uygula; önce kayıt adlarından seçim yap, en yeni güncel çerçeveyi ve ilgili tecrübeleri oku. Sonraki çalışmayı etkileyen bir sonuç, öğrenilen ders veya durum değişikliği oluştuğunda ayrıca istenmesini beklemeden yeni tarihli kayıt ekle. Eski kayıtları düzenlemeye dayalı bir sistem kurma. En az tokenla okuma ve yazma hedefi yalnızca Walkthrough içindir; diğer işlerde tasarruf yapılması veya yapılmaması konusunda hüküm koymaz.
