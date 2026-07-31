const fs = require('fs');
const { Pool } = require('pg');

// PostgreSQL Bağlantı Bilgilerin
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'gis_staj',
    password: '1234',
    port: 5432,
});

async function veriAktar() {
    const client = await pool.connect();
    try {
        console.log("1. PostGIS uzantısı kontrol ediliyor...");
        await client.query('CREATE EXTENSION IF NOT EXISTS postgis;');

        console.log("2. Eski tablo temizleniyor/oluşturuluyor...");
        // Tabloyu sıfırdan oluşturuyoruz (id, özellikler ve geometri kolonu)
        await client.query('DROP TABLE IF EXISTS osm_verileri;');
        await client.query(`
            CREATE TABLE osm_verileri (
                id SERIAL PRIMARY KEY,
                properties JSONB,
                geom GEOMETRY(Geometry, 4326)
            );
        `);

        console.log("3. GeoJSON dosyası okunuyor (Bu işlem dosya boyutundan dolayı birkaç saniye sürebilir)...");
        const dosyaIcerigi = fs.readFileSync('export.geojson', 'utf8');
        const geojson = JSON.parse(dosyaIcerigi);

        console.log(`4. Toplam ${geojson.features.length} adet veri bulundu. Aktarım başlıyor...`);

        // Performans için işlemleri tek bir transaction (işlem) içinde yapıyoruz
        await client.query('BEGIN');

        const insertQuery = `
            INSERT INTO osm_verileri (properties, geom) 
            VALUES ($1, ST_GeomFromGeoJSON($2))
        `;

        for (let i = 0; i < geojson.features.length; i++) {
            const feature = geojson.features[i];
            
            // Geometri veya özellik boşsa hata vermemesi için kontrol
            const properties = feature.properties || {};
            const geometry = JSON.stringify(feature.geometry);

            await client.query(insertQuery, [properties, geometry]);

            // Her 5000 kayıtta bir ilerleme durumunu konsola yazdır
            if ((i + 1) % 5000 === 0) {
                console.log(`> ${i + 1} veri aktarıldı...`);
            }
        }

        await client.query('COMMIT');
        
        // Coğrafi sorguların hızlı çalışması için index (endeks) oluşturuyoruz
        console.log("5. Mekansal indeks (Spatial Index) oluşturuluyor...");
        await client.query('CREATE INDEX osm_verileri_geom_idx ON osm_verileri USING gist(geom);');

        console.log("🎉 Başarılı! Tüm veriler 'gis_staj' veritabanındaki 'osm_verileri' tablosuna aktarıldı.");

    } catch (hata) {
        await client.query('ROLLBACK');
        console.error("❌ Aktarım sırasında bir hata oluştu:", hata);
    } finally {
        client.release();
        await pool.end();
    }
}

veriAktar();