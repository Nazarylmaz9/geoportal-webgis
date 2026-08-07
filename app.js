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

// ============================================================
// 📜 ADRES/BİNA BAZLI DEĞİŞİKLİK GEÇMİŞİ (VERSİYONLAMA) YARDIMCISI
// Genel "islem_gecmisi"nden farklı olarak, burada eski/yeni değerleri
// JSONB olarak saklıyoruz ki bir binanın zaman içindeki tüm alan
// değişikliklerini (örn. yapı durumu insaat -> ruhsatli) gösterebilelim.
// ============================================================
async function adresGecmisiKaydet(adresId, kullaniciId, degisiklikTipi, eskiDeger, yeniDeger, aciklama = null) {
    try {
        await pool.query(
            `INSERT INTO adres_gecmisi (adres_id, kullanici_id, degisiklik_tipi, eski_deger, yeni_deger, aciklama)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [
                adresId,
                kullaniciId,
                degisiklikTipi,
                eskiDeger ? JSON.stringify(eskiDeger) : null,
                yeniDeger ? JSON.stringify(yeniDeger) : null,
                aciklama,
            ],
        );
    } catch (err) {
        console.error('Adres geçmişi kaydedilemedi:', err.message);
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

// 🔍 AKILLI TÜM KATMANLARDA ARAMA API'Sİ
app.get('/api/arama', girisGerekli, async (req, res) => {
    const { q } = req.query;
    if (!q || q.trim().length < 2) {
        return res.json({ noktalar: [], binalar: [] });
    }

    const aranan = `%${q.trim().toLowerCase()}%`;

    try {
        // 1. CBS Noktalarında Ara
        const noktaRes = await pool.query(
            `SELECT id, isim, tip, ST_X(geom) as lng, ST_Y(geom) as lat
             FROM cbs_noktalar
             WHERE (silindi_mi IS FALSE OR silindi_mi IS NULL)
               AND (lower(isim) LIKE $1 OR lower(tip) LIKE $1)
             LIMIT 10`,
            [aranan]
        );

        // 2. Bina / Adres Kayıtlarında Ara
        const binaRes = await pool.query(
            `SELECT id, il, ilce, mahalle, sokak, dis_kapi_no, bina_adi, yapi_durumu, ST_X(geom) as lng, ST_Y(geom) as lat
             FROM adresler
             WHERE (silindi_mi IS FALSE OR silindi_mi IS NULL)
               AND durum = 'onaylandi'
               AND (lower(mahalle) LIKE $1 OR lower(sokak) LIKE $1 OR lower(bina_adi) LIKE $1)
             LIMIT 10`,
            [aranan]
        );

        res.json({
            noktalar: noktaRes.rows,
            binalar: binaRes.rows
        });
    } catch (err) {
        console.error("Arama hatası:", err);
        res.status(500).json({ error: "Arama yapılırken hata oluştu." });
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
            const eslesen = await pool.query(
                `SELECT id FROM adresler
                 WHERE ST_Equals(geom, ST_SetSRID(ST_MakePoint($1, $2), 4326))
                 ORDER BY id DESC LIMIT 1`,
                [log.lng, log.lat],
            );
            if (eslesen.rows.length > 0) {
                const adresId = eslesen.rows[0].id;
                await pool.query(`UPDATE adresler SET silindi_mi = TRUE WHERE id = $1`, [adresId]);
                await adresGecmisiKaydet(
                    adresId,
                    req.kullanici.id,
                    'SILINDI',
                    null,
                    null,
                    `${req.kullanici.ad_soyad} tarafından silindi (geçmiş kaydı üzerinden).`,
                );
            }
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
                            'durum', a.durum,
                            'olusturmaTarihi', a.olusturma_tarihi
                        )
                    )
                ), '[]'::jsonb)
            ) AS geojson
            FROM (
                SELECT * FROM adresler a
                WHERE (a.silindi_mi IS FALSE OR a.silindi_mi IS NULL)
                  AND a.durum = 'onaylandi'
                  ${yetkiKosulu} ${metinKosulu}
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
        // 🛡️ ONAY AKIŞI: Tam yetkili (admin/Genel Müdürlük) kullanıcının
        // eklediği kayıtlar direkt onaylı sayılır; diğer kullanıcıların
        // kayıtları "beklemede" olarak başlar ve admin onayı bekler.
        const baslangicDurumu = req.kullanici.tam_yetki ? 'onaylandi' : 'beklemede';

        const insertQuery = `
            INSERT INTO adresler
                (il, ilce, mahalle, sokak, dis_kapi_no, bina_adi, kat_sayisi, bagimsiz_bolum_sayisi, yapi_durumu, durum, geom, ekleyen_kullanici_id)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, ST_SetSRID(ST_MakePoint($11, $12), 4326), $13)
            RETURNING id;
        `;
        const result = await pool.query(insertQuery, [
            il, ilce, mahalle, sokak || null, disKapiNo || null, binaAdi || null,
            katSayisi || 0, bagimsizBolumSayisi || 0, yapiDurumu, baslangicDurumu, lng, lat, req.kullanici.id,
        ]);

        const yeniId = result.rows[0].id;

        await adresGecmisiKaydet(
            yeniId,
            req.kullanici.id,
            'OLUSTURULDU',
            null,
            { il, ilce, mahalle, sokak, disKapiNo, binaAdi, katSayisi, bagimsizBolumSayisi, yapiDurumu, durum: baslangicDurumu },
            `${req.kullanici.ad_soyad} tarafından oluşturuldu.`,
        );

        await islemLogKaydet(
            req.kullanici.id,
            'ADRES_EKLEME',
            `"${mahalle}, ${sokak || '-'} ${disKapiNo || ''}" adresine yeni bina kaydı eklendi (${yapiDurumu})` +
                (baslangicDurumu === 'beklemede' ? ' — onay bekliyor.' : '.'),
            lat,
            lng,
        );

        res.status(201).json({
            message:
                baslangicDurumu === 'beklemede'
                    ? 'Bina/adres kaydınız oluşturuldu ve yönetici onayına gönderildi.'
                    : 'Bina/adres kaydı başarıyla eklendi!',
            id: yeniId,
            durum: baslangicDurumu,
        });
    } catch (err) {
        console.error('Adres ekleme hatası:', err);
        res.status(500).json({ error: 'Adres kaydedilirken veritabanı hatası oluştu.' });
    }
});

// ============================================================
// 🛡️ ONAY AKIŞI (SADECE ADMİN / GENEL MÜDÜRLÜK)
// ============================================================

// 📋 Onay bekleyen tüm kayıtları listele (tüm bölgeler, admin görür)
app.get('/api/adresler/beklemede', girisGerekli, adminGerekli, async (req, res) => {
    try {
        const sonuc = await pool.query(
            `SELECT
                a.id, a.il, a.ilce, a.mahalle, a.sokak, a.dis_kapi_no, a.bina_adi,
                a.kat_sayisi, a.bagimsiz_bolum_sayisi, a.yapi_durumu, a.olusturma_tarihi,
                k.ad_soyad AS ekleyen_ad_soyad, k.bolge AS ekleyen_bolge
             FROM adresler a
             LEFT JOIN kullanicilar k ON k.id = a.ekleyen_kullanici_id
             WHERE (a.silindi_mi IS FALSE OR a.silindi_mi IS NULL)
               AND a.durum = 'beklemede'
             ORDER BY a.olusturma_tarihi ASC`,
        );
        res.json(sonuc.rows);
    } catch (err) {
        console.error('Bekleyen kayıtlar hatası:', err);
        res.status(500).json({ error: 'Bekleyen kayıtlar alınamadı.' });
    }
});
// ✅ Bir kaydı onayla + Kullanıcıya Bildirim Gönder
app.post('/api/adresler/:id/onayla', girisGerekli, adminGerekli, async (req, res) => {
    try {
        const mevcut = await pool.query(`SELECT * FROM adresler WHERE id = $1`, [req.params.id]);
        if (mevcut.rows.length === 0) {
            return res.status(404).json({ error: 'Kayıt bulunamadı.' });
        }
        const eski = mevcut.rows[0];

        await pool.query(`UPDATE adresler SET durum = 'onaylandi' WHERE id = $1`, [req.params.id]);

        // 🔔 KULLANICIYA BİLDİRİM OLUŞTUR
        if (eski.ekleyen_kullanici_id) {
            await pool.query(
                `INSERT INTO bildirimler (kullanici_id, baslik, mesaj)
                 VALUES ($1, $2, $3)`,
                [
                    eski.ekleyen_kullanici_id,
                    ' Bina Kaydınız Onaylandı!',
                    `"${eski.mahalle}, ${eski.sokak || '-'}" adresinde girdiğiniz bina kaydı yönetici tarafından onaylandı ve haritada yayınlandı.`
                ]
            );
        }

        await adresGecmisiKaydet(
            req.params.id,
            req.kullanici.id,
            'ONAYLANDI',
            { durum: eski.durum },
            { durum: 'onaylandi' },
            `${req.kullanici.ad_soyad} tarafından onaylandı.`,
        );

        res.json({ message: 'Kayıt onaylandı.' });
    } catch (err) {
        console.error('Onaylama hatası:', err);
        res.status(500).json({ error: 'Kayıt onaylanırken hata oluştu.' });
    }
});

// ❌ Bir kaydı reddet + Kullanıcıya Bildirim Gönder
app.post('/api/adresler/:id/reddet', girisGerekli, adminGerekli, async (req, res) => {
    try {
        const { sebep } = req.body;
        const mevcut = await pool.query(`SELECT * FROM adresler WHERE id = $1`, [req.params.id]);
        if (mevcut.rows.length === 0) {
            return res.status(404).json({ error: 'Kayıt bulunamadı.' });
        }
        const eski = mevcut.rows[0];

        await pool.query(
            `UPDATE adresler SET durum = 'reddedildi', red_sebebi = $2 WHERE id = $1`,
            [req.params.id, sebep || null],
        );

        // 🔔 KULLANICIYA RED BİLDİRİMİ OLUŞTUR
        if (eski.ekleyen_kullanici_id) {
            await pool.query(
                `INSERT INTO bildirimler (kullanici_id, baslik, mesaj)
                 VALUES ($1, $2, $3)`,
                [
                    eski.ekleyen_kullanici_id,
                    ' Bina Kaydınız Reddedildi',
                    `"${eski.mahalle}, ${eski.sokak || '-'}" adresli bina kaydınız reddedildi.` + (sebep ? ` Gerekçe: ${sebep}` : '')
                ]
            );
        }

        res.json({ message: 'Kayıt reddedildi.' });
    } catch (err) {
        console.error('Reddetme hatası:', err);
        res.status(500).json({ error: 'Kayıt reddedilirken hata oluştu.' });
    }
});

// 🔔 BİLDİRİM BİLGİSİ ÇEKME & SAYI HESAPLAMA API'Sİ
app.get('/api/bildirimler', girisGerekli, async (req, res) => {
    try {
        let beklemedeSayisi = 0;
        
        // Eğer giriş yapan kullanıcı admin ise onay bekleyen bina sayısını da getir
        if (req.kullanici.tam_yetki) {
            const bekleyenRes = await pool.query(
                `SELECT COUNT(*) FROM adresler WHERE (silindi_mi IS FALSE OR silindi_mi IS NULL) AND durum = 'beklemede'`
            );
            beklemedeSayisi = parseInt(bekleyenRes.rows[0].count) || 0;
        }

        // Kullanıcının okunmamış bildirimlerini getir
        const bildirimRes = await pool.query(
            `SELECT * FROM bildirimler WHERE kullanici_id = $1 ORDER BY olusturma_tarihi DESC LIMIT 50`,
            [req.kullanici.id]
        );

        const okunmamisSayisi = bildirimRes.rows.filter(b => !b.okundu).length;

        res.json({
            beklemedeSayisi,
            okunmamisSayisi,
            bildirimler: bildirimRes.rows
        });
    } catch (err) {
        console.error("Bildirim çekme hatası:", err);
        res.status(500).json({ error: "Bildirimler alınamadı." });
    }
});

// 🔔 BİLDİRİMLERİ OKUNDU İŞARETLEME API'Sİ
app.post('/api/bildirimler/okundu', girisGerekli, async (req, res) => {
    try {
        await pool.query(`UPDATE bildirimler SET okundu = TRUE WHERE kullanici_id = $1`, [req.kullanici.id]);
        res.json({ message: "Bildirimler okundu." });
    } catch (err) {
        res.status(500).json({ error: "İşlem başarısız." });
    }
});

// 📋 Kullanıcının SADECE kendi eklediği onay bekleyen bina kayıtlarını getirir
app.get('/api/adresler/benim-bekleyenlerim', girisGerekli, async (req, res) => {
    try {
        const sonuc = await pool.query(
            `SELECT id, il, ilce, mahalle, sokak, dis_kapi_no, bina_adi, yapi_durumu, olusturma_tarihi
             FROM adresler
             WHERE ekleyen_kullanici_id = $1
               AND (silindi_mi IS FALSE OR silindi_mi IS NULL)
               AND durum = 'beklemede'
             ORDER BY olusturma_tarihi DESC`,
            [req.kullanici.id]
        );
        res.json(sonuc.rows);
    } catch (err) {
        console.error('Kullanıcı bekleyen kayıtlar hatası:', err);
        res.status(500).json({ error: 'Bekleyen kayıtlarınız alınamadı.' });
    }
});

// ============================================================
// ✏️ BİNA/ADRES KAYDINI GÜNCELLEME (versiyon geçmişine işlenir)
// ============================================================
app.put('/api/adresler/:id', girisGerekli, async (req, res) => {
    const {
        mahalle, sokak, disKapiNo, binaAdi,
        katSayisi, bagimsizBolumSayisi, yapiDurumu,
    } = req.body;

    const GECERLI_DURUMLAR = ['ruhsatli', 'ruhsatsiz', 'insaat', 'yikik'];
    if (yapiDurumu && !GECERLI_DURUMLAR.includes(yapiDurumu)) {
        return res.status(400).json({ error: 'Geçersiz yapı durumu.' });
    }

    try {
        const mevcut = await pool.query(
            `SELECT * FROM adresler WHERE id = $1 AND (silindi_mi IS FALSE OR silindi_mi IS NULL)`,
            [req.params.id],
        );
        if (mevcut.rows.length === 0) {
            return res.status(404).json({ error: 'Kayıt bulunamadı veya silinmiş.' });
        }
        const eski = mevcut.rows[0];

        const yeni = {
            mahalle: mahalle ?? eski.mahalle,
            sokak: sokak ?? eski.sokak,
            dis_kapi_no: disKapiNo ?? eski.dis_kapi_no,
            bina_adi: binaAdi ?? eski.bina_adi,
            kat_sayisi: katSayisi ?? eski.kat_sayisi,
            bagimsiz_bolum_sayisi: bagimsizBolumSayisi ?? eski.bagimsiz_bolum_sayisi,
            yapi_durumu: yapiDurumu ?? eski.yapi_durumu,
        };

        await pool.query(
            `UPDATE adresler SET
                mahalle = $1, sokak = $2, dis_kapi_no = $3, bina_adi = $4,
                kat_sayisi = $5, bagimsiz_bolum_sayisi = $6, yapi_durumu = $7
             WHERE id = $8`,
            [
                yeni.mahalle, yeni.sokak, yeni.dis_kapi_no, yeni.bina_adi,
                yeni.kat_sayisi, yeni.bagimsiz_bolum_sayisi, yeni.yapi_durumu,
                req.params.id,
            ],
        );

        await adresGecmisiKaydet(
            req.params.id,
            req.kullanici.id,
            'GUNCELLENDI',
            {
                mahalle: eski.mahalle, sokak: eski.sokak, dis_kapi_no: eski.dis_kapi_no,
                bina_adi: eski.bina_adi, kat_sayisi: eski.kat_sayisi,
                bagimsiz_bolum_sayisi: eski.bagimsiz_bolum_sayisi, yapi_durumu: eski.yapi_durumu,
            },
            yeni,
            `${req.kullanici.ad_soyad} tarafından güncellendi.`,
        );

        await islemLogKaydet(
            req.kullanici.id,
            'ADRES_GUNCELLEME',
            `"${yeni.mahalle}, ${yeni.sokak || '-'}" adresli bina kaydı (#${req.params.id}) güncellendi.`,
        );

        res.json({ message: 'Kayıt güncellendi.' });
    } catch (err) {
        console.error('Adres güncelleme hatası:', err);
        res.status(500).json({ error: 'Kayıt güncellenirken hata oluştu.' });
    }
});

// 📜 Bir binanın versiyon/değişiklik geçmişini listele
app.get('/api/adresler/:id/gecmis', girisGerekli, async (req, res) => {
    try {
        const sonuc = await pool.query(
            `SELECT
                g.id, g.degisiklik_tipi, g.eski_deger, g.yeni_deger, g.aciklama, g.olusturma_tarihi,
                k.ad_soyad AS kullanici_ad_soyad
             FROM adres_gecmisi g
             LEFT JOIN kullanicilar k ON k.id = g.kullanici_id
             WHERE g.adres_id = $1
             ORDER BY g.olusturma_tarihi ASC`,
            [req.params.id],
        );
        res.json(sonuc.rows);
    } catch (err) {
        console.error('Adres geçmişi çekme hatası:', err);
        res.status(500).json({ error: 'Değişiklik geçmişi alınamadı.' });
    }
});

// 🏠 BAĞIMSIZ BÖLÜM EKLEME (Kullanıcı ID Garantili Düzeltme)
app.post('/api/adresler/:id/bagimsiz-bolumler', girisGerekli, async (req, res) => {
    const { id } = req.params;
    const { kapiNo, kullanimTuru, katNo } = req.body;

    // Middleware'in atadığı nesneye göre kullanıcı ID'sini yakala
    const kullanici = req.user || req.kullanici || {};
    const ekleyenId = kullanici.id || kullanici.kullanici_id || null;

    if (!kapiNo) {
        return res.status(400).json({ error: "Kapı numarası gereklidir." });
    }

    try {
        const result = await pool.query(
            `INSERT INTO bagimsiz_bolumler (adres_id, kapi_no, kullanim_turu, kat_no, ekleyen_kullanici_id)
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [id, kapiNo, kullanimTuru || 'mesken', Number(katNo) || 0, ekleyenId]
        );

        // Bina bağımsız bölüm sayısını otomatik güncelle
        await pool.query(
            `UPDATE adresler 
             SET bagimsiz_bolum_sayisi = (SELECT COUNT(*) FROM bagimsiz_bolumler WHERE adres_id = $1)
             WHERE id = $1`,
            [id]
        );

        res.json({ message: "Bağımsız bölüm başarıyla eklendi.", bagimsizBolum: result.rows[0] });
    } catch (err) {
        console.error("Bağımsız bölüm ekleme hatası:", err);
        res.status(500).json({ error: "Sunucu hatası oluştu." });
    }
});
// 📜 BİNANIN BAĞIMSIZ BÖLÜMLERİNİ GETİRME (KATA GÖRE SIRALI)
app.get('/api/adresler/:id/bagimsiz-bolumler', girisGerekli, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(
            `SELECT id, kapi_no, kullanim_turu, kat_no 
             FROM bagimsiz_bolumler 
             WHERE adres_id = $1 
             ORDER BY kat_no ASC, kapi_no ASC`,
            [id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error("Bağımsız bölüm çekme hatası:", err);
        res.status(500).json({ error: "Sunucu hatası." });
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

// 📐 POLİGON İÇİ KESİŞİM ANALİZİ (Garantili & Temiz PostGIS Versiyonu)
app.post('/api/analiz/kesisim', girisGerekli, async (req, res) => {
    const { geometry } = req.body;

    if (!geometry) {
        return res.status(400).json({ error: "Geçerli bir poligon geometrisi gereklidir." });
    }

    try {
        const geojsonStr = JSON.stringify(geometry);

        // 1. Poligon içinde kalan CBS Noktalarını (POI) bul
        const noktalarSorgu = await pool.query(
            `SELECT id, isim, tip, ST_Y(geom::geometry) as lat, ST_X(geom::geometry) as lng 
             FROM cbs_noktalar 
             WHERE ST_Contains(ST_SetSRID(ST_GeomFromGeoJSON($1), 4326), geom::geometry)`,
            [geojsonStr]
        );

        // 2. Poligon içinde kalan Binaları/Adresleri bul
        const binalarSorgu = await pool.query(
            `SELECT id, mahalle, sokak, dis_kapi_no, bina_adi, yapi_durumu, bagimsiz_bolum_sayisi,
                    ST_Y(geom::geometry) as lat, ST_X(geom::geometry) as lng 
             FROM adresler 
             WHERE ST_Contains(ST_SetSRID(ST_GeomFromGeoJSON($1), 4326), geom::geometry)`,
            [geojsonStr]
        );

        res.json({
            toplamEleman: noktalarSorgu.rows.length + binalarSorgu.rows.length,
            noktalar: noktalarSorgu.rows,
            binalar: binalarSorgu.rows
        });
    } catch (err) {
        console.error("Kesişim analizi hatası:", err);
        res.status(500).json({ error: "Mekânsal analiz sırasında sunucu hatası oluştu.", detay: err.message });
    }
});

// 📍 EN YAKIN TESİS TESPİTİ (Nearest Neighbor / K-NN)
app.post('/api/analiz/en-yakin-tesis', girisGerekli, async (req, res) => {
    const { lat, lng, tip } = req.body; // tip opsiyonel (Örn: 'hastane', 'okul' veya hepsi)

    if (!lat || !lng) {
        return res.status(400).json({ error: "Geçerli bir enlem ve boylam (lat, lng) gereklidir." });
    }

    try {
        let sorguEk = "";
        const params = [lng, lat];

        if (tip && tip !== 'hepsi') {
            sorguEk = "WHERE tip = $3";
            params.push(tip);
        }

        // PostGIS ST_DistanceSpheroid veya ST_DistanceSphere ile metre cinsinden en yakın 1 noktayı bulma
        const sql = `
            SELECT id, isim, tip, 
                   ST_Y(geom::geometry) as lat, 
                   ST_X(geom::geometry) as lng,
                   ROUND(ST_DistanceSphere(geom::geometry, ST_SetSRID(ST_MakePoint($1, $2), 4326))::numeric, 1) as mesafe_metre
            FROM cbs_noktalar
            ${sorguEk}
            ORDER BY geom::geometry <-> ST_SetSRID(ST_MakePoint($1, $2), 4326)
            LIMIT 1;
        `;

        const result = await pool.query(sql, params);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Yakında herhangi bir tesis veya CBS noktası bulunamadı." });
        }

        res.json({
            enYakinTesis: result.rows[0]
        });
    } catch (err) {
        console.error("En yakın tesis analizi hatası:", err);
        res.status(500).json({ error: "En yakın tesis hesaplanırken sunucu hatası oluştu.", detay: err.message });
    }
});
// 🔐 JWT Token Doğrulama Middleware
const yetkiKontrolu = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Erişim yetkisi yok (Token bulunamadı).' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'gizli_anahtar', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Geçersiz veya süresi dolmuş token.' });
    }
    req.user = user;
    next();
  });
};
// 📜 1. Kayıtlı Çizimleri Getirme (Sadece aktif olan "is_active = true" kayıtlar çekilir)
app.get('/api/cizimler', async (req, res) => {
  try {
    const kullaniciId = req.query.kullanici_id;
    const isTamYetki = req.query.tam_yetki === 'true';

    let query = "SELECT * FROM cizimler WHERE is_active = TRUE ORDER BY id DESC";
    let params = [];

    // Admin (tam yetki) değilse sadece oturum açan kullanıcının AKTİF çizimlerini çek
    if (!isTamYetki && kullaniciId) {
      query = "SELECT * FROM cizimler WHERE kullanici_id = $1 AND is_active = TRUE ORDER BY id DESC";
      params = [kullaniciId];
    }

    const result = await pool.query(query, params);
    res.json(result.rows || []);
  } catch (err) {
    console.error("GET /api/cizimler Hatası:", err);
    res.status(500).json({ error: "Çizimler veritabanından alınamadı." });
  }
});

// 💾 2. Yeni Çizim Kaydetme (Varsayılan olarak is_active = true eklenir)
app.post('/api/cizimler', async (req, res) => {
  try {
    const { baslik, cizim_tipi, geojson_data, kullanici_id, kullanici_adi } = req.body;

    const geojsonObj = typeof geojson_data === 'string' ? geojson_data : JSON.stringify(geojson_data);

    const result = await pool.query(
      `INSERT INTO cizimler (kullanici_id, kullanici_adi, baslik, cizim_tipi, geojson_data, is_active) 
       VALUES ($1, $2, $3, $4, $5::jsonb, TRUE) RETURNING *`,
      [
        kullanici_id || null, 
        kullanici_adi || 'Bilinmeyen Kullanıcı', 
        baslik, 
        cizim_tipi || 'Karma Vektör', 
        geojsonObj
      ]
    );

    res.json({ message: "Çizim kaydedildi!", cizim: result.rows[0] });
  } catch (err) {
    console.error("POST /api/cizimler Hatası:", err);
    res.status(500).json({ error: "Çizim veritabanına kaydedilemedi." });
  }
});

// 🗑️ 3. Çizim Silme (SOFT DELETE — Veriyi fiziksel silmez, is_active = FALSE yapar)
app.delete('/api/cizimler/:id', async (req, res) => {
  try {
    const cizimId = req.params.id;

    // DELETE FROM yerine UPDATE ile pasife alıyoruz
    await pool.query("UPDATE cizimler SET is_active = FALSE WHERE id = $1", [cizimId]);

    res.json({ message: "Çizim başarıyla pasife alındı (Soft Delete)." });
  } catch (err) {
    console.error("DELETE /api/cizimler Hatası:", err);
    res.status(500).json({ error: "Çizim pasife alınamadı." });
  }
});
app.listen(PORT, () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor! `);
});