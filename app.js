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
/*/ 3. NOKTA (POINTS) API'Sİ (GET)
app.get('/api/noktalar', async (req, res) => {
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
              'id',         id,
              'isim',       isim,
              'tip',        tip
            )
          ) AS feature
          FROM cbs_noktalar
        ) features;
        `;
        const result = await pool.query(query);
        res.json(result.rows[0].jsonb_build_object || { type: "FeatureCollection", features: [] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Noktalar çekilirken hata oluştu' });
    }
});*/

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
// 8. TAMPON BÖLGE (BUFFER) ANALİZİ API'Sİ
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