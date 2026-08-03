const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 5000;

// ⚠️ Bunu gerçek projede .env dosyasına taşı (process.env.JWT_SECRET).
// Staj/geliştirme ortamı için burada sabit tutuyoruz.
const JWT_SECRET = 'cbs-staj-projesi-gizli-anahtar-2026';
const JWT_GECERLILIK = '8h';

// Gelen JSON verilerini okuyabilmek için
app.use(express.json());
app.use(cors()); // Tarayıcı güvenlik engelini aşmak için

// PostgreSQL Bağlantı Havuzu Ayarları
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'gis_staj',
    password: '1234', 
    port: 5432,
    max: 10,
    statement_timeout: 15000,
});

// Statik dosyaları sunmak için klasör tanımı
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// 🔐 AUTH MIDDLEWARE: Authorization: Bearer <token> başlığını
// doğrular ve doğrulanan kullanıcıyı req.kullanici'ye koyar.
// ============================================================
function girisGerekli(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
        return res.status(401).json({ error: 'Oturum bulunamadı, lütfen giriş yapın.' });
    }

    try {
        req.kullanici = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Oturum süresi dolmuş veya geçersiz, lütfen tekrar giriş yapın.' });
    }
}

// ============================================================
// 🛡️ ADMIN MIDDLEWARE: girisGerekli'den SONRA çalışır, req.kullanici
// üzerindeki tam_yetki bayrağını kontrol eder. Admin olmayan bir
// kullanıcı admin rotalarına 403 alır.
// ============================================================
function adminGerekli(req, res, next) {
    if (!req.kullanici || !req.kullanici.tam_yetki) {
        return res.status(403).json({ error: 'Bu işlem için yönetici yetkisi gereklidir.' });
    }
    next();
}

// ============================================================
// 📜 İŞLEM GEÇMİŞİ (AUDIT LOG) KAYIT YARDIMCI FONKSİYONU
// ============================================================
async function islemLogKaydet(kullaniciId, islemTipi, aciklama, lat = null, lng = null) {
    try {
        await pool.query(
            `INSERT INTO islem_gecmisi (kullanici_id, islem_tipi, aciklama, lat, lng)
             VALUES ($1, $2, $3, $4, $5)`,
            [kullaniciId, islemTipi, aciklama, lat, lng],
        );
    } catch (err) {
        // Log kaydı başarısız olsa bile asıl işlemi engellemeyelim, sadece uyar
        console.error('İşlem geçmişi kaydedilemedi:', err.message);
    }
}

// 1. ANA SAYFA ROTASI
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================
// 🔑 GİRİŞ (LOGIN) API'Sİ
// Kullanıcı adı + şifreyi veritabanındaki kullanicilar tablosuyla
// karşılaştırır (bcrypt/pgcrypto ile), doğruysa bir JWT üretir.
// ============================================================
app.post('/api/login', async (req, res) => {
    const { kullanici_adi, sifre } = req.body;

    if (!kullanici_adi || !sifre) {
        return res.status(400).json({ error: 'Kullanıcı adı ve şifre gereklidir.' });
    }

    try {
        const sonuc = await pool.query(
            `SELECT id, kullanici_adi, ad_soyad, rol, bolge, il_kodu, tam_yetki
             FROM kullanicilar
             WHERE kullanici_adi = $1
               AND aktif = TRUE
               AND sifre_hash = crypt($2, sifre_hash)`,
            [kullanici_adi.trim().toLowerCase(), sifre],
        );

        if (sonuc.rows.length === 0) {
            return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı!' });
        }

        const kullanici = sonuc.rows[0];

        const token = jwt.sign(
            {
                id: kullanici.id,
                kullanici_adi: kullanici.kullanici_adi,
                ad_soyad: kullanici.ad_soyad,
                rol: kullanici.rol,
                bolge: kullanici.bolge,
                il_kodu: kullanici.il_kodu,
                tam_yetki: kullanici.tam_yetki,
            },
            JWT_SECRET,
            { expiresIn: JWT_GECERLILIK },
        );

        await islemLogKaydet(kullanici.id, 'GIRIS', `${kullanici.ad_soyad} sisteme giriş yaptı.`);

        res.json({ token, user: kullanici });
    } catch (err) {
        console.error('Giriş hatası:', err);
        res.status(500).json({ error: 'Giriş sırasında sunucu hatası oluştu.' });
    }
});

// ============================================================
// 🚪 ÇIKIŞ (LOGOUT) API'Sİ
// JWT stateless olduğu için sunucuda "iptal" edilmez; burada sadece
// çıkış olayını işlem geçmişine kaydediyoruz.
// ============================================================
app.post('/api/logout', girisGerekli, async (req, res) => {
    await islemLogKaydet(req.kullanici.id, 'CIKIS', `${req.kullanici.ad_soyad} oturumu kapattı.`);
    res.json({ message: 'Çıkış kaydedildi.' });
});

// ============================================================
// 📜 GEÇMİŞ İŞLEMLERİM API'Sİ
// Giriş yapmış kullanıcının kendi işlem geçmişini döner.
// ============================================================
app.get('/api/gecmis', girisGerekli, async (req, res) => {
    try {
        const sonuc = await pool.query(
            `SELECT islem_tipi, aciklama, lat, lng, olusturma_tarihi
             FROM islem_gecmisi
             WHERE kullanici_id = $1
             ORDER BY olusturma_tarihi DESC
             LIMIT 200`,
            [req.kullanici.id],
        );
        res.json(sonuc.rows);
    } catch (err) {
        console.error('Geçmiş çekme hatası:', err);
        res.status(500).json({ error: 'İşlem geçmişi alınamadı.' });
    }
});

// ============================================================
// 🛡️ ADMIN: TÜM KULLANICILARIN İŞLEM GEÇMİŞİ
// Sadece tam_yetki=true olan (admin) kullanıcılar erişebilir.
// İsteğe bağlı ?kullanici_id= filtresiyle tek bir kullanıcıya
// daraltılabilir.
// ============================================================
app.get('/api/admin/gecmis', girisGerekli, adminGerekli, async (req, res) => {
    try {
        const { kullanici_id } = req.query;
        const parametreler = [];
        let kosul = '';
        if (kullanici_id) {
            parametreler.push(kullanici_id);
            kosul = `WHERE g.kullanici_id = $${parametreler.length}`;
        }

        const sonuc = await pool.query(
            `SELECT g.id, g.kullanici_id, g.islem_tipi, g.aciklama, g.lat, g.lng, g.olusturma_tarihi,
                    k.kullanici_adi, k.ad_soyad, k.rol
             FROM islem_gecmisi g
             LEFT JOIN kullanicilar k ON k.id = g.kullanici_id
             ${kosul}
             ORDER BY g.olusturma_tarihi DESC
             LIMIT 500`,
            parametreler,
        );
        res.json(sonuc.rows);
    } catch (err) {
        console.error('Admin geçmiş çekme hatası:', err);
        res.status(500).json({ error: 'İşlem geçmişi alınamadı.' });
    }
});

// 🛡️ ADMIN: İŞLEM GEÇMİŞİ VE İLİŞKİLİ VERİYİ SOFT DELETE İLE SİLME
app.delete('/api/admin/gecmis/:id', girisGerekli, adminGerekli, async (req, res) => {
    try {
        const { id } = req.params;

        // 1. Önce silinecek log kaydını bulalım
        const logRes = await pool.query(`SELECT * FROM islem_gecmisi WHERE id = $1`, [id]);
        if (logRes.rows.length === 0) {
            return res.status(404).json({ error: 'Log kaydı bulunamadı.' });
        }

        const log = logRes.rows[0];

        // 2. Eğer bir Nokta Ekleme eylemiyse cbs_noktalar tablosunda soft delete yap
        if (log.islem_tipi === 'NOKTA_EKLEME' && log.lat && log.lng) {
            await pool.query(
                `UPDATE cbs_noktalar 
                 SET silindi_mi = TRUE 
                 WHERE id = (
                     SELECT id FROM cbs_noktalar 
                     WHERE ST_Equals(geom, ST_SetSRID(ST_MakePoint($1, $2), 4326)) 
                     ORDER BY id DESC LIMIT 1
                 )`,
                [log.lng, log.lat]
            );
        }
        // 3. Eğer bir Adres/Bina Ekleme eylemiyse adresler tablosunda soft delete yap
        else if (log.islem_tipi === 'ADRES_EKLEME' && log.lat && log.lng) {
            await pool.query(
                `UPDATE adresler 
                 SET silindi_mi = TRUE 
                 WHERE id = (
                     SELECT id FROM adresler 
                     WHERE ST_Equals(geom, ST_SetSRID(ST_MakePoint($1, $2), 4326)) 
                     ORDER BY id DESC LIMIT 1
                 )`,
                [log.lng, log.lat]
            );
        }

        // 4. İşlem geçmişi kaydını temizle
        await pool.query(`DELETE FROM islem_gecmisi WHERE id = $1`, [id]);

        await islemLogKaydet(
            req.kullanici.id,
            'GECMIS_SILME',
            `Yönetici tarafından #${id} numaralı kayıt ve ilişkili coğrafi veri pasife çekildi (Soft Delete).`
        );

        res.json({ message: 'Kayıt ve ilişkili veri başarıyla silindi.' });
    } catch (err) {
        console.error('Admin geçmiş silme hatası:', err);
        res.status(500).json({ error: 'Kayıt silinirken hata oluştu.' });
    }
});

// ============================================================
// 📝 GENEL AKTİVİTE LOGLAMA API'Sİ
// Çizim, GeoJSON yükleme, WFS sorgusu, rapor alma, adres arama gibi
// tamamen tarayıcı tarafında gerçekleşen ama geçmişte görünmesi
// gereken eylemler için frontend bu endpoint'i çağırır.
// ============================================================
app.post('/api/gecmis/log', girisGerekli, async (req, res) => {
    const { islem_tipi, aciklama, lat, lng } = req.body;
    if (!islem_tipi) {
        return res.status(400).json({ error: 'islem_tipi zorunludur.' });
    }
    await islemLogKaydet(req.kullanici.id, islem_tipi, aciklama || null, lat ?? null, lng ?? null);
    res.status(201).json({ message: 'Kaydedildi.' });
});

// 2. POLİGON (İL SINIRLARI) API'Sİ
app.get("/api/iller", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT json_build_object(
        'type', 'FeatureCollection',
        'features', json_agg(
          json_build_object(
            'type', 'Feature',
            'geometry', ST_AsGeoJSON(ST_SimplifyPreserveTopology(geom, 0.001))::json,
            'properties', json_build_object(
              'il_adi', COALESCE(NULLIF(nl_name_1, 'NA'), name_1),
              'isim', COALESCE(NULLIF(nl_name_1, 'NA'), name_1),
              'tip', 'İl',
              'nufus', COALESCE(nufus, 500000)
            )
          )
        )
      ) AS geojson FROM gadm41_tur_1;
    `);
    res.json(result.rows[0].geojson);
  } catch (err) {
    console.error("İller API Hatası:", err);
    res.status(500).send("Veri çekilemedi.");
  }
});
// 3. CBS NOKTALARI API'Sİ (GET - SPATIAL YETKİLİ)
app.get('/api/noktalar', girisGerekli, async (req, res) => {
    try {
        const yetkiKosulu = yetkiKosuluUret(req.kullanici, 'n.geom');

        const query = `
        SELECT jsonb_build_object(
            'type',     'FeatureCollection',
            'features', COALESCE(jsonb_agg(features.feature), '[]'::jsonb)
        )
        FROM (
          SELECT jsonb_build_object(
            'type',       'Feature',
            'id',         id,
            'geometry',   ST_AsGeoJSON(geom)::jsonb,
            'properties', jsonb_build_object(
              'id',         id,
              'isim',       isim,
              'tip',        tip
            )
          ) AS feature
          FROM cbs_noktalar n
          WHERE (n.silindi_mi IS FALSE OR n.silindi_mi IS NULL) ${yetkiKosulu}
        ) features;
        `;
        const result = await pool.query(query);
        res.json(result.rows[0].jsonb_build_object || { type: "FeatureCollection", features: [] });
    } catch (err) {
        console.error('Noktalar çekilirken hata:', err);
        res.status(500).json({ error: 'Noktalar çekilirken hata oluştu' });
    }
});

/*/ 4. ÇİZGİ (LINESTRINGS) API'Sİ (GET)
app.get('/api/yollar', async (req, res) => {
    try {
        const query = `
        SELECT jsonb_build_object(
            'type',     'FeatureCollection',
            'features', jsonb_agg(features.feature)
        )
        FROM (
          SELECT jsonb_build_object(
            'type',       'Feature',
            'id',         id,
            'geometry',   ST_AsGeoJSON(geom)::jsonb,
            'properties', jsonb_build_object(
              'isim', isim,
              'tip', tip
            )
          ) AS feature
          FROM cbs_cizgiler
        ) features;
        `;
        const result = await pool.query(query);
        res.json(result.rows[0].jsonb_build_object);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Yollar çekilirken hata oluştu' });
    }
});*/

// 5. YENİ NOKTA EKLEME API'Sİ (POST)
app.post('/api/noktalar', girisGerekli, async (req, res) => {
    const { isim, tip, lat, lng } = req.body;
    
    if (!isim || !tip || !lat || !lng) {
        return res.status(400).json({ error: 'Eksik bilgi gönderildi.' });
    }

    try {
        const insertQuery = `
            INSERT INTO cbs_noktalar (isim, tip, geom) 
            VALUES ($1, $2, ST_SetSRID(ST_MakePoint($3, $4), 4326))
            RETURNING id;
        `;
        const result = await pool.query(insertQuery, [isim, tip, lng, lat]);

        await islemLogKaydet(
            req.kullanici.id,
            'NOKTA_EKLEME',
            `"${isim}" (${tip}) adlı nokta eklendi.`,
            lat,
            lng,
        );

        res.status(201).json({ message: 'Nokta başarıyla kaydedildi!', id: result.rows[0].id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Veri kaydedilirken veritabanı hatası oluştu.' });
    }
});

// 6. MEKANSAL ANALİZ API'Sİ: Noktanın En Yakın Yola Uzaklığını Hesaplama
app.get('/api/analiz/mesafe/:nokta_id', async (req, res) => {
    const noktaId = req.params.nokta_id;

    try {
        const query = `
            SELECT 
                n.isim AS nokta_adi,
                y.isim AS yol_adi,
                ROUND(ST_Distance(n.geom::geography, y.geom::geography)) AS mesafe_metre
            FROM cbs_noktalar n
            CROSS JOIN cbs_cizgiler y
            WHERE n.id = $1
            ORDER BY mesafe_metre ASC
            LIMIT 1;
        `;

        const result = await pool.query(query, [noktaId]);

        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ error: "Analiz edilecek veri bulunamadı." });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Mekansal analiz sırasında veritabanı hatası oluştu." });
    }
});

// 7. OSM VERİLERİ API'Sİ (Zengin Gerçek Mekan Verileri)
// İsteğe bağlı bbox parametreleri (minLng, minLat, maxLng, maxLat) ile
// yalnızca belirli bir dikdörtgen alandaki noktalar çekilebilir. Front-end
// bunu, giriş yapan kullanıcının yetki bölgesinin sınır kutusunu göndererek
// kullanır: hem performans kazandırır hem de yetki kontrolüne ek bir
// veritabanı seviyesi katmanı ekler (kesin poligon filtresi client tarafında
// turf.js ile ayrıca uygulanır).
app.get('/api/harita-verileri', async (req, res) => {
    try {
        const { minLng, minLat, maxLng, maxLat } = req.query;
        const bboxVerildi =
            minLng !== undefined &&
            minLat !== undefined &&
            maxLng !== undefined &&
            maxLat !== undefined &&
            [minLng, minLat, maxLng, maxLat].every((v) => !isNaN(parseFloat(v)));

        const bboxKosulu = bboxVerildi
            ? `AND ST_Intersects(geom, ST_MakeEnvelope($1, $2, $3, $4, 4326))`
            : '';

        // 🎯 DENGELİ SORGU: her kategori kendi kotasına (LIMIT) sahip, bu
        // sayede "tarihi/turistik" gibi kalabalık bir kategori diğerlerini
        // (sağlık, eğitim, finans...) toplam kotadan silip süpüremiyor.
        // historic artık "IS NOT NULL" değil, sadece anlamlı/büyük alt
        // türlerle sınırlandırıldı (küçük sınır taşı, yol kenarı haçı gibi
        // binlerce mikro-etiket elenmiş oldu).
        const sorgu = `
            WITH saglik AS (
                SELECT id, properties, geom
                FROM osm_verileri
                WHERE properties->>'name' IS NOT NULL
                  AND properties->>'amenity' IN ('hospital', 'clinic', 'pharmacy', 'dentist', 'doctors')
                  ${bboxKosulu}
                LIMIT 300
            ),
            egitim AS (
                SELECT id, properties, geom
                FROM osm_verileri
                WHERE properties->>'name' IS NOT NULL
                  AND properties->>'amenity' IN ('school', 'university', 'college', 'kindergarten', 'library')
                  ${bboxKosulu}
                LIMIT 300
            ),
            ibadet AS (
                SELECT id, properties, geom
                FROM osm_verileri
                WHERE properties->>'name' IS NOT NULL
                  AND properties->>'amenity' = 'place_of_worship'
                  ${bboxKosulu}
                LIMIT 200
            ),
            sosyal AS (
                SELECT id, properties, geom
                FROM osm_verileri
                WHERE properties->>'name' IS NOT NULL
                  AND (
                      properties->>'amenity' IN ('restaurant', 'cafe', 'fast_food', 'bar', 'pub')
                      OR properties->>'tourism' IN ('hotel', 'guest_house', 'hostel', 'motel')
                  )
                  ${bboxKosulu}
                LIMIT 300
            ),
            finans AS (
                SELECT id, properties, geom
                FROM osm_verileri
                WHERE properties->>'name' IS NOT NULL
                  AND properties->>'amenity' IN ('bank', 'atm')
                  ${bboxKosulu}
                LIMIT 150
            ),
            tarihi AS (
                SELECT id, properties, geom
                FROM osm_verileri
                WHERE properties->>'name' IS NOT NULL
                  AND (
                      properties->>'tourism' IN ('museum', 'attraction', 'gallery', 'zoo', 'theme_park')
                      OR properties->>'historic' IN ('castle', 'monument', 'ruins', 'archaeological_site', 'memorial', 'fort', 'tomb', 'citywalls')
                  )
                  ${bboxKosulu}
                LIMIT 300
            ),
            diger AS (
                SELECT id, properties, geom
                FROM osm_verileri
                WHERE properties->>'name' IS NOT NULL
                  AND (
                      properties->>'amenity' IN ('townhall', 'police', 'fire_station', 'marketplace', 'fuel', 'post_office')
                      OR properties->>'aeroway' IS NOT NULL
                  )
                  ${bboxKosulu}
                LIMIT 150
            )
            SELECT jsonb_build_object(
                'type', 'FeatureCollection',
                'features', jsonb_agg(features.feature)
            ) as geojson
            FROM (
                SELECT jsonb_build_object(
                    'type', 'Feature',
                    'id', id,
                    'geometry', ST_AsGeoJSON(geom)::jsonb,
                    'properties', jsonb_build_object(
                        'isim', COALESCE(properties->>'name', 'İsimsiz Mekan'),
                        'tip', COALESCE(properties->>'amenity', properties->>'tourism', properties->>'historic', 'Nokta'),
                        'kategori', CASE 
                            WHEN properties->>'amenity' IS NOT NULL THEN properties->>'amenity'
                            WHEN properties->>'tourism' IS NOT NULL THEN properties->>'tourism'
                            WHEN properties->>'historic' IS NOT NULL THEN properties->>'historic'
                            ELSE 'Diğer'
                        END
                    )
                ) AS feature
                FROM (
                    SELECT * FROM saglik
                    UNION ALL SELECT * FROM egitim
                    UNION ALL SELECT * FROM ibadet
                    UNION ALL SELECT * FROM sosyal
                    UNION ALL SELECT * FROM finans
                    UNION ALL SELECT * FROM tarihi
                    UNION ALL SELECT * FROM diger
                ) inputs
            ) features;
        `;

        const parametreler = bboxVerildi
            ? [parseFloat(minLng), parseFloat(minLat), parseFloat(maxLng), parseFloat(maxLat)]
            : [];

        const sonuc = await pool.query(sorgu, parametreler);

        if (!sonuc.rows[0] || !sonuc.rows[0].geojson) {
            return res.json({ type: "FeatureCollection", features: [] });
        }

        res.json(sonuc.rows[0].geojson);

    } catch (hata) {
        console.error("OSM Veri çekme hatası:", hata);
        res.status(500).json({ error: "Veritabanı hatası oluştu." });
    }
});
// ============================================================
// 📍 YENİ POI VERİLERİ API'Sİ (GÜVENLİ VE SPATIAL YETKİLİ)
// Yeni oluşturduğumuz osm_poi tablosundan verileri çeker.
// Giriş yapan kullanıcının rolüne/bölgesine göre veritabanı
// seviyesinde PostGIS ST_Intersects / ST_Within filtresi uygular.
// ============================================================
app.get('/api/poi-verileri', girisGerekli, async (req, res) => {
    try {
        const kullanici = req.kullanici;
        const { bolge, tam_yetki } = kullanici;

        // Yetki kısıtlamalarını tutacak koşul dizisi
        let kosullar = [];

        // 🛡️ 1. İşe yaramaz / kategorisiz noktaları eliyoruz (Sadece gerçek POI'ler)
        kosullar.push(`p.kategori IS NOT NULL AND p.kategori != 'diger'`);

        // 🛡️ 2. SPATIAL YETKİ FİLTRESİ (Admin değilse bölgesine kilitler)
        if (!tam_yetki) {
            if (bolge === "Ankara İli") {
                kosullar.push(`ST_Intersects(p.geom, (
                    SELECT geom FROM gadm41_tur_1 WHERE lower(name_1) LIKE '%ankara%' OR lower(nl_name_1) LIKE '%ankara%' LIMIT 1
                ))`);
            } else if (bolge === "İç Anadolu Bölgesi") {
                kosullar.push(`ST_Intersects(p.geom, (
                    SELECT ST_Union(geom) FROM gadm41_tur_1 
                    WHERE lower(name_1) IN ('ankara', 'eskisehir', 'kayseri', 'konya', 'sivas', 'kirikkale', 'aksaray', 'karaman', 'kirsehir', 'nigde', 'nevsehir', 'yozgat', 'cankiri')
                       OR lower(nl_name_1) IN ('ankara', 'eskişehir', 'kayseri', 'konya', 'sivas', 'kırıkkale', 'aksaray', 'karaman', 'kırşehir', 'niğde', 'nevşehir', 'yozgat', 'çankırı')
                ))`);
            } else if (bolge === "Yenimahalle İlçesi") {
                kosullar.push(`ST_Intersects(p.geom, ST_MakeEnvelope(32.65, 39.90, 32.85, 40.08, 4326))`);
            }
        }

        // Tüm koşulları WHERE ile birleştiriyoruz (WHERE hatasını engeller)
        const whereMetni = kosullar.length > 0 ? `WHERE ${kosullar.join(' AND ')}` : '';

        const sorgu = `
            SELECT jsonb_build_object(
                'type', 'FeatureCollection',
                'features', COALESCE(jsonb_agg(
                    jsonb_build_object(
                        'type', 'Feature',
                        'id', p.id,
                        'geometry', ST_AsGeoJSON(p.geom)::jsonb,
                        'properties', jsonb_build_object(
                            'id', p.id,
                            'isim', COALESCE(p.name, 'İsimsiz Mekan'),
                            'name', COALESCE(p.name, 'İsimsiz Mekan'),
                            'kategori', COALESCE(p.kategori, 'diger'),
                            'amenity', p.amenity,
                            'healthcare', p.healthcare,
                            'tourism', p.tourism,
                            'shop', p.shop,
                            'detay', p.properties
                        )
                    )
                ), '[]'::jsonb)
            ) AS geojson
            FROM (
                SELECT * FROM public.osm_poi p
                ${whereMetni}
                LIMIT 1500
            ) p;
        `;

        const sonuc = await pool.query(sorgu);
        const geojson = sonuc.rows[0]?.geojson || { type: "FeatureCollection", features: [] };

        res.json(geojson);

    } catch (err) {
        console.error("POI Veri Çekme Hatası:", err);
        res.status(500).json({ error: "POI verileri çekilirken veritabanı hatası oluştu." });
    }
});
// ============================================================
// 🏠 BİNA / ADRES KAYIT MODÜLÜ (MAKS BENZERİ)
// ============================================================

// Ortak yardımcı: giriş yapan kullanıcının yetki bölgesine göre
// SQL WHERE koşulunu üretir (poi-verileri route'undaki mantığın aynısı,
// tek bir yerde tutmak yerine burada da tekrar ediyoruz ki route'lar
// birbirinden bağımsız kalsın).
function yetkiKosuluUret(kullanici, geomIfadesi) {
    const { bolge, tam_yetki } = kullanici;
    if (tam_yetki) return '';

    if (bolge === 'Ankara İli') {
        return `AND ST_Intersects(${geomIfadesi}, (
            SELECT geom FROM gadm41_tur_1 WHERE lower(name_1) LIKE '%ankara%' OR lower(nl_name_1) LIKE '%ankara%' LIMIT 1
        ))`;
    } else if (bolge === 'İç Anadolu Bölgesi') {
        return `AND ST_Intersects(${geomIfadesi}, (
            SELECT ST_Union(geom) FROM gadm41_tur_1
            WHERE lower(name_1) IN ('ankara', 'eskisehir', 'kayseri', 'konya', 'sivas', 'kirikkale', 'aksaray', 'karaman', 'kirsehir', 'nigde', 'nevsehir', 'yozgat', 'cankiri')
               OR lower(nl_name_1) IN ('ankara', 'eskişehir', 'kayseri', 'konya', 'sivas', 'kırıkkale', 'aksaray', 'karaman', 'kırşehir', 'niğde', 'nevşehir', 'yozgat', 'çankırı')
        ))`;
    } else if (bolge === 'Yenimahalle İlçesi') {
        return `AND ST_Intersects(${geomIfadesi}, ST_MakeEnvelope(32.65, 39.90, 32.85, 40.08, 4326))`;
    }
    return '';
}
// 📍 BİNA/ADRES LİSTESİ
app.get('/api/adresler', girisGerekli, async (req, res) => {
    try {
        const { mahalle, sokak } = req.query;
        const yetkiKosulu = yetkiKosuluUret(req.kullanici, 'a.geom');

        const parametreler = [];
        let metinKosulu = '';
        if (mahalle) {
            parametreler.push(`%${mahalle.toLowerCase()}%`);
            metinKosulu += ` AND lower(a.mahalle) LIKE $${parametreler.length}`;
        }
        if (sokak) {
            parametreler.push(`%${sokak.toLowerCase()}%`);
            metinKosulu += ` AND lower(a.sokak) LIKE $${parametreler.length}`;
        }

        const sorgu = `
            SELECT jsonb_build_object(
                'type', 'FeatureCollection',
                'features', COALESCE(jsonb_agg(
                    jsonb_build_object(
                        'type', 'Feature',
                        'id', a.id,
                        'geometry', ST_AsGeoJSON(a.geom)::jsonb,
                        'properties', jsonb_build_object(
                            'id', a.id,
                            'il', a.il,
                            'ilce', a.ilce,
                            'mahalle', a.mahalle,
                            'sokak', a.sokak,
                            'disKapiNo', a.dis_kapi_no,
                            'binaAdi', a.bina_adi,
                            'katSayisi', a.kat_sayisi,
                            'bagimsizBolumSayisi', a.bagimsiz_bolum_sayisi,
                            'yapiDurumu', a.yapi_durumu,
                            'olusturmaTarihi', a.olusturma_tarihi
                        )
                    )
                ), '[]'::jsonb)
            ) AS geojson
            FROM (
                SELECT * FROM adresler a
                WHERE (a.silindi_mi IS FALSE OR a.silindi_mi IS NULL) ${yetkiKosulu} ${metinKosulu}
                ORDER BY a.olusturma_tarihi DESC
                LIMIT 1000
            ) a;
        `;

        const sonuc = await pool.query(sorgu, parametreler);
        res.json(sonuc.rows[0]?.geojson || { type: 'FeatureCollection', features: [] });
    } catch (err) {
        console.error('Adres listesi hatası:', err);
        res.status(500).json({ error: 'Adres verileri çekilirken hata oluştu.' });
    }
});

// 🏠 YENİ BİNA/ADRES KAYDI EKLEME
app.post('/api/adresler', girisGerekli, async (req, res) => {
    const {
        il, ilce, mahalle, sokak, disKapiNo, binaAdi,
        katSayisi, bagimsizBolumSayisi, yapiDurumu, lat, lng,
    } = req.body;

    if (!il || !ilce || !mahalle || !yapiDurumu || lat === undefined || lng === undefined) {
        return res.status(400).json({ error: 'İl, ilçe, mahalle, yapı durumu ve konum bilgisi zorunludur.' });
    }

    const GECERLI_DURUMLAR = ['ruhsatli', 'ruhsatsiz', 'insaat', 'yikik'];
    if (!GECERLI_DURUMLAR.includes(yapiDurumu)) {
        return res.status(400).json({ error: 'Geçersiz yapı durumu.' });
    }

    try {
        const insertQuery = `
            INSERT INTO adresler
                (il, ilce, mahalle, sokak, dis_kapi_no, bina_adi, kat_sayisi, bagimsiz_bolum_sayisi, yapi_durumu, geom, ekleyen_kullanici_id)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, ST_SetSRID(ST_MakePoint($10, $11), 4326), $12)
            RETURNING id;
        `;
        const result = await pool.query(insertQuery, [
            il, ilce, mahalle, sokak || null, disKapiNo || null, binaAdi || null,
            katSayisi || 0, bagimsizBolumSayisi || 0, yapiDurumu, lng, lat, req.kullanici.id,
        ]);

        await islemLogKaydet(
            req.kullanici.id,
            'ADRES_EKLEME',
            `"${mahalle}, ${sokak || '-'} ${disKapiNo || ''}" adresine yeni bina kaydı eklendi (${yapiDurumu}).`,
            lat,
            lng,
        );

        res.status(201).json({ message: 'Bina/adres kaydı başarıyla eklendi!', id: result.rows[0].id });
    } catch (err) {
        console.error('Adres ekleme hatası:', err);
        res.status(500).json({ error: 'Adres kaydedilirken veritabanı hatası oluştu.' });
    }
});

// 📋 BİR BİNANIN BAĞIMSIZ BÖLÜMLERİNİ LİSTELEME
app.get('/api/adresler/:id/bagimsiz-bolumler', girisGerekli, async (req, res) => {
    try {
        const sonuc = await pool.query(
            `SELECT id, kapi_no, kullanim_turu, olusturma_tarihi
             FROM bagimsiz_bolumler
             WHERE adres_id = $1
             ORDER BY kapi_no ASC`,
            [req.params.id],
        );
        res.json(sonuc.rows);
    } catch (err) {
        console.error('Bağımsız bölüm listesi hatası:', err);
        res.status(500).json({ error: 'Bağımsız bölümler alınamadı.' });
    }
});

// 📋 BİR BİNAYA YENİ BAĞIMSIZ BÖLÜM (DAİRE/İŞYERİ) EKLEME
app.post('/api/adresler/:id/bagimsiz-bolumler', girisGerekli, async (req, res) => {
    const { kapiNo, kullanimTuru } = req.body;
    if (!kapiNo || !kullanimTuru) {
        return res.status(400).json({ error: 'Kapı no ve kullanım türü zorunludur.' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO bagimsiz_bolumler (adres_id, kapi_no, kullanim_turu, ekleyen_kullanici_id)
             VALUES ($1, $2, $3, $4)
             RETURNING id`,
            [req.params.id, kapiNo, kullanimTuru, req.kullanici.id],
        );

        // Binadaki toplam bağımsız bölüm sayısını da otomatik güncelleyelim
        await pool.query(
            `UPDATE adresler SET bagimsiz_bolum_sayisi = (
                SELECT COUNT(*) FROM bagimsiz_bolumler WHERE adres_id = $1
             ) WHERE id = $1`,
            [req.params.id],
        );

        await islemLogKaydet(
            req.kullanici.id,
            'BAGIMSIZ_BOLUM_EKLEME',
            `Bina #${req.params.id} için "${kapiNo}" numaralı bağımsız bölüm eklendi (${kullanimTuru}).`,
        );

        res.status(201).json({ message: 'Bağımsız bölüm kaydedildi!', id: result.rows[0].id });
    } catch (err) {
        console.error('Bağımsız bölüm ekleme hatası:', err);
        res.status(500).json({ error: 'Bağımsız bölüm kaydedilirken hata oluştu.' });
    }
});


app.post('/api/analiz/buffer', girisGerekli, async (req, res) => {
  const { geometry, distance } = req.body;

  if (!geometry || !distance) {
    return res.status(400).json({ error: 'Geometri veya mesafe bilgisi eksik.' });
  }

  try {
    // ST_Buffer metrik hesaplama yapsın diye geography tipine çevirip sorguluyoruz
    const query = `
      SELECT ST_AsGeoJSON(
        ST_Buffer(
          ST_SetSRID(ST_GeomFromGeoJSON($1), 4326)::geography, 
          $2
        )::geometry
      ) AS buffer_json;
    `;

    const result = await pool.query(query, [JSON.stringify(geometry), distance]);

    if (result.rows[0] && result.rows[0].buffer_json) {
      await islemLogKaydet(
        req.kullanici.id,
        'BUFFER_ANALIZ',
        `${distance} metre yarıçapında tampon bölge analizi yapıldı.`,
      );
      res.json(JSON.parse(result.rows[0].buffer_json));
    } else {
      res.status(500).json({ error: 'Tampon bölge oluşturulamadı.' });
    }
  } catch (err) {
    console.error('Buffer Hatası:', err);
    res.status(500).json({ error: 'Veritabanı analiz hatası.' });
  }
});
app.listen(PORT, () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde tıkır tıkır çalışıyor! 🚀`);
});