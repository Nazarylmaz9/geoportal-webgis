const fs = require('fs');
const { Pool } = require('pg');

// Veritabanı Bağlantısı (Kendi şifreni yaz aşkım!)
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'gis_staj',
    password: 'YOUR_DATABASE_PASSWORD', // <--- PostgreSQL şifreni buraya yaz aşkım!
    port: 5432,
});

async function importGeoJSON() {
    try {
        console.log("GeoJSON okunuyor...");
        // export.geojson dosyasının proje klasöründe olduğundan emin ol
        const rawData = fs.readFileSync('export.geojson', 'utf-8');
        const geojson = JSON.parse(rawData);

        console.log(`Toplam ${geojson.features.length} adet veri bulundu. Aktarım başlıyor...`);

        let yolSayac = 0;
        let noktaSayac = 0;

        for (const feature of geojson.features) {
            const geom = feature.geometry;
            const props = feature.properties;

            // Eğer geometri boşsa veya geçersizse atla
            if (!geom || !geom.coordinates) continue;

            const isim = props.name || props.highway || props.tourism || props.historical || "İsimsiz Mekan";

            if (geom.type === 'LineString' || geom.type === 'MultiLineString') {
                const tip = props.highway === 'motorway' ? 'Otoyol' : 'Devlet Yolu';
                const query = `
                    INSERT INTO cbs_cizgiler (isim, tip, geom)
                    VALUES ($1, $2, ST_SetSRID(ST_GeomFromGeoJSON($3), 4326))
                `;
                await pool.query(query, [isim, tip, JSON.stringify(geom)]);
                yolSayac++;
            } else if (geom.type === 'Point') {
                const tip = props.tourism ? 'Turistik Mekan' : (props.historical ? 'Tarihi Eser / Antik Kent' : 'Doğal Yapı');
                const query = `
                    INSERT INTO cbs_noktalar (isim, tip, geom)
                    VALUES ($1, $2, ST_SetSRID(ST_GeomFromGeoJSON($3), 4326))
                `;
                await pool.query(query, [isim, tip, JSON.stringify(geom)]);
                noktaSayac++;
            }
        }

        console.log(`✅ AKTARIM TAMAMLANDI!`);
        console.log(`📊 Eklenen Yol Sayısı: ${yolSayac}`);
        console.log(`📊 Eklenen Nokta Sayısı: ${noktaSayac}`);

    } catch (err) {
        console.error("Aktarım sırasında hata çıktı:", err);
    } finally {
        await pool.end();
    }
}

importGeoJSON();