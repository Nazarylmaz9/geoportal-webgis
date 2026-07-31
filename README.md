🌍 GeoPortal - Türkiye Web GIS Platformu
GeoPortal; PostgreSQL/PostGIS veritabanı altyapısı, Node.js/Express backend servisi ve Leaflet.js tabanlı ön yüzü ile geliştirilmiş, Rol Tabanlı Erişim Kontrolü (RBAC) ve Mekansal Yetkilendirme (Spatial Access Control) özelliklerine sahip dinamik bir Web Coğrafi Bilgi Sistemi (CBS) uygulamasıdır.

Proje; farklı idari yetki seviyelerine sahip kullanıcıların sadece izin verilen coğrafi sınırlar içerisindeki mekansal verileri görüntülemesine, analiz etmesine ve yönetmesine olanak tanır.

🚀 Öne Çıkan Özellikler
Rol ve Bölge Tabanlı Mekansal Yetkilendirme (RBAC & Spatial Filtering):

Admin: Tüm Türkiye sınırları genelinde tam yetki.

İç Anadolu Bölge Yöneticisi: Sadece İç Anadolu Bölgesi'ndeki 13 ili kapsayan dinamik MultiPolygon yetki sınırı.

Ankara İl Temsilcisi: Sadece Ankara il sınırları dahilinde veri erişimi.

Yenimahalle İlçe Müdürü: Hassas çizilmiş ilçe sınır poligonu ile kısıtlanmış bölgesel alan yetkisi.

Güvenli Yetki Kısıtlamaları & Öznitelik Gizleme:

Kullanıcının yetki alanı dışındaki mekanlara tıklandığında detaylı öznitelik erişimi engellenir (Yetki Dışı Veri uyarısı).

Yetki bölgesi dışına çizim yapılması, buffer analizi çalıştırılması veya adres araması ile haritanın odaklanması veritabanı ve istemci seviyesinde engellenir.

Mekansal Analiz Araçları:

Tampon Bölge (Buffer) Analizi: Seçilen geometri etrafında metrik uzaklık tabanlı PostGIS ST_Buffer analizi.

En Yakın Yol Analizi: Nokta verisinin en yakın ulaşım ağına olan mesafesinin metre cinsinden hesaplanması (ST_Distance).

Dinamik İstatistik & Lejant Paneli:

Harita ekranındaki ve yetki alanındaki noktalara göre anlık olarak güncellenen kategori bazlı istatistik ve lejant paneli.

İşlem Geçmişi (Audit Logging):

Kullanıcıların giriş/çıkış hareketleri, çizim aksiyonları ve çalıştırdıkları analizlerin zaman/konum bilgisiyle PostgreSQL veritabanına kaydedilmesi.

🛠️ Teknoloji Yığını
Backend & Veritabanı
Node.js & Express.js: RESTful API mimarisi ve yetkilendirme servisleri.

PostgreSQL & PostGIS: Mekansal verilerin (Point, LineString, Polygon) depolanması ve mekansal sorgular (ST_Intersects, ST_Buffer, ST_AsGeoJSON).

JWT (JSON Web Token) & Pgcrypto: Güvenli oturum yönetimi ve veritabanı seviyesinde şifrelenmiş kimlik doğrulama.

Frontend & Harita Motoru
Leaflet.js: İnteraktif harita katmanları ve marker yönetimi.

Turf.js: İstemci (client) tarafında nokta-poligon (booleanPointInPolygon) ve bounding box (bbox) mekansal kontrolleri.

HTML5, CSS3, JavaScript (ES6+): Modern ve esnek GeoPortal arayüz tasarımı.

📁 Veritabanı Mimarisi
Sistem arkasında aşağıdaki temel PostGIS tablolarını kullanır:

gadm41_tur_1: Türkiye il idari sınır poligonları.

osm_verileri / osm_poi: Türkiye geneli OpenStreetMap yol ağları ve kategori etiketli POI (İlgi Noktası) verileri.

kullanicilar: Kullanıcı bilgileri, şifre hash'leri, rol ve idari bölge tanımları.

islem_gecmisi: Sistem içi loglama ve audit verileri.

💻 Kurulum ve Çalıştırma
Gereksinimler:

Node.js (v18+)

PostgreSQL (v14+) ve PostGIS Eklentisi

Projeyi Klonlayın:
git clone https://github.com/KullaniciAdin/proje-adin.git
cd proje-adin

Bağımlılıkları Yükleyin:
npm install

Veritabanı Bağlantısını Yapılandırın:
app.js içerisindeki PostgreSQL havuz (Pool) ayarlarını kendi veritabanı bilgilerinize göre güncelleyin.

Sunucuyu Başlatın:
node app.js

Sunucu çalıştıktan sonra tarayıcınızdan http://localhost:5000 adresine giderek GeoPortal arayüzüne erişebilirsiniz.

🔑 Örnek Kullanıcı Rolleri
admin -> Genel Sistem Yöneticisi -> Tüm Türkiye

icanadolu -> Bölge Yöneticisi -> İç Anadolu Bölgesi (13 İl)

ankara -> İl Temsilcisi -> Ankara İli

yenimahalle -> İlçe Müdürü -> Yenimahalle İlçesi













