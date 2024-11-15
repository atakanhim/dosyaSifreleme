import crypto from "crypto";
import fs from "fs";
// encrypted dizininin var olup olmadığını kontrol et

// Kullanıcı şifresinden anahtar türetme
function deriveKeyFromPassword(password, salt) {
    // Şifreyi önce hashle (SHA-256)
    const hashedPassword = crypto.createHash("sha256").update(password).digest();
    // scrypt ile anahtar türetme (salt ile birlikte)
    return crypto.scryptSync(hashedPassword, salt, 32); // 32 bayt uzunluğunda anahtar
}
// SHA-256 Hash ile dosya adını oluşturma
function generateFileNameFromHash(filePath, iv) {
    const hash = crypto.createHash("sha256");
    hash.update(filePath + iv); // Dosya yolunu hash'liyoruz
    return hash.digest("hex"); // SHA-256 hash değeri
}
function returnPathAsArray(path) {
    let baseUrl = "";
    let filename = "";
    let ext = "";
    // En son ' / ' karakterinin bulunduğu konumu buluyoruz
    const lastSlashIndex = path.lastIndexOf("/");
    if (lastSlashIndex !== -1) {
        // ' / ' konumuna göre baseUrl ve kalan kısmı ayırıyoruz
        baseUrl = path.slice(0, lastSlashIndex); // Base URL
        filename = path.slice(lastSlashIndex + 1); // ' / ' sonrası kısmı filename olarak alıyoruz
    } else {
        // Eğer ' / ' yoksa, bütün path filename olarak alınır
        filename = path;
    }
    // En son ' . ' karakterinin bulunduğu konumu buluyoruz
    const lastDotIndex = filename.lastIndexOf(".");
    if (lastDotIndex !== -1) {
        // ' . ' konumuna göre filename ve ext'i ayırıyoruz
        ext = filename.slice(lastDotIndex + 1); // ' . ' sonrası extension
        filename = filename.slice(0, lastDotIndex); // ' . ' öncesi filename
    }

    return {
        filename: filename,
        fileExtension: ext,
        url: baseUrl,
    };
}

async function decryptFile(encryptedFilePath, password) {
    const input = fs.createReadStream(encryptedFilePath);

    return new Promise((resolve, reject) => {
        let header = Buffer.alloc(36); // Salt (16) + IV (16) + Metadata Length (4)
        let metadata = '';
        let decipher;

        input.once('data', async (chunk) => {
            try {
                // İlk 36 baytı okuyarak Salt, IV ve Metadata uzunluğunu alıyoruz
                header = chunk.slice(0, 36);
                const salt = header.slice(0, 16);
                const iv = header.slice(16, 32);
                const metadataLength = header.readUInt32BE(32); // Metadata uzunluğu

                const metadataBuffer = chunk.slice(36, 36 + metadataLength);
                metadata = metadataBuffer.toString('utf-8');
                const [filename, extension] = metadata.split('|');

                console.log('Çözülen Metadata:', { filename, extension });

                const derivedKey = deriveKeyFromPassword(password, salt);

                // Decipher akışı oluşturuluyor
                decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);

                const remainingChunk = chunk.slice(36 + metadataLength);
                let outputFileName = `./decrypted/${filename}.${extension}`;
                let outputFileNameJson = returnPathAsArray(outputFileName);
                outputFileName = await incrementOutputPath(outputFileNameJson); // Path kontrolü ve artırımı

                const output = fs.createWriteStream(outputFileName);

                if (remainingChunk.length > 0) {
                    decipher.write(remainingChunk);
                }

                // Tüm veri akışlarını bağlama
                input.pipe(decipher).pipe(output);

                // Hata ve başarı yönetimi
                input.on('error', reject);
                decipher.on('error', reject);
                output.on('error', reject);
                output.on('finish', () => resolve(outputFileName));
            } catch (err) {
                reject(err);
            }
        });

        input.on('error', reject);
    });
}


function encryptFile(inputPath, password) {
    const iv = crypto.randomBytes(16); // Rastgele IV oluşturma
    const salt = crypto.randomBytes(16); // Rastgele salt oluşturma
    const derivedKey = deriveKeyFromPassword(password, salt); // Şifreden anahtar türetme
    const orjinalPathData = returnPathAsArray(inputPath); // Yolun verilerini çözme
    const metadata = `${orjinalPathData.filename}|${orjinalPathData.fileExtension}`; // Metadata (isim ve uzantı)
    const metadataBuffer = Buffer.from(metadata, 'utf-8');
    const metadataLengthBuffer = Buffer.alloc(4); // Metadata uzunluğu için 4 byte
    metadataLengthBuffer.writeUInt32BE(metadataBuffer.length, 0);

    const encryptedFileName = generateFileNameFromHash(inputPath, iv);
    const encryptedFilePath = `./encrypted/${encryptedFileName}.enc`;

    return new Promise((resolve, reject) => {
        const input = fs.createReadStream(inputPath);
        const output = fs.createWriteStream(encryptedFilePath);

        // Dosyanın başına salt, IV, metadata uzunluğu ve metadata yazılıyor
        output.write(Buffer.concat([salt, iv, metadataLengthBuffer, metadataBuffer]), (err) => {
            if (err) return reject(err);

            const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
            input.pipe(cipher).pipe(output);

            // Hata ve başarı yönetimi
            input.on('error', reject);
            cipher.on('error', reject);
            output.on('error', reject);
            output.on('finish', () => resolve(encryptedFilePath));
        });
    });
}
async function incrementOutputPath(data) {
    // Base URL, filename, ve extension için değişkenler tanımlıyoruz
    let newFilename = `${data.filename}`;
    let newPath = `${data.url}/${newFilename}.${data.fileExtension}`;
    // Asenkron dosya mevcutluk kontrolü
    if (fs.existsSync(newPath)) {
        newFilename = await generateUniqueFilename(data);
        newPath = `${data.url}/${newFilename}.${data.fileExtension}`;
    }
    return newPath; // Mevcut olmayan yeni yolu döndür
}

// Benzersiz dosya adı oluşturma fonksiyonu
function generateUniqueFilename(data) {
    let counter = 1;
    let newFilename = `${data.filename}_${counter}`;
    let newPath = `${data.url}/${newFilename}.${data.fileExtension}`;

    // Dosya mevcut olduğu sürece numarayı artırarak yeni isim denemeye devam et
    while (fs.existsSync(newPath)) {
        counter += 1;
        newFilename = `${data.filename}_${counter}`;
        newPath = `${data.baseUrl}/${newFilename}.${data.fileExtension}`;
    }

    return newFilename; // Benzersiz dosya adı
} 
// Ana işlem kısmını async/await ile düzenleyelim
 function main() {
    // Yeni bir şifre oluştur
    try {
        const inputPath = "./normaldosya/askerlik.JPEG";

        encryptFile(inputPath, "sifre123")
            .then((encryptedFilePath) => {
                console.log(`Dosya başarıyla çözüldü: ${encryptedFilePath}`);
            })
            .catch((err) => {
                console.error("Şifre çözme sırasında hata oluştu:", err);
            });;
    } catch (error) {
        console.error("Error:", error);
    }
}
 function main2() {
    try {
        decryptFile(
            "./encrypted/96ebf6eba6c24a4fcc3c383fff49b72fa7a74695226910791d88474f4708eb53.enc",
            "sifre123"
        )
            .then((decryptedFilePath) => {
                console.log(`Dosya başarıyla çözüldü: ${decryptedFilePath}`);
            })
            .catch((err) => {
                console.error("Şifre çözme sırasında hata oluştu:", err);
            });
    } catch (error) {
        console.error("Error:", error);
    }
}

main2();

/*

function returnPathAsArray(path) {
    let baseUrl = '';
    let filename = '';
    let ext = '';
    // En son ' / ' karakterinin bulunduğu konumu buluyoruz
    const lastSlashIndex = path.lastIndexOf('/');
    if (lastSlashIndex !== -1) {
        // ' / ' konumuna göre baseUrl ve kalan kısmı ayırıyoruz
        baseUrl = path.slice(0, lastSlashIndex); // Base URL
        filename = path.slice(lastSlashIndex + 1); // ' / ' sonrası kısmı filename olarak alıyoruz
    } else {
        // Eğer ' / ' yoksa, bütün path filename olarak alınır
        filename = path;
    }
    // En son ' . ' karakterinin bulunduğu konumu buluyoruz
    const lastDotIndex = filename.lastIndexOf('.');
    if (lastDotIndex !== -1) {
        // ' . ' konumuna göre filename ve ext'i ayırıyoruz
        ext = filename.slice(lastDotIndex + 1); // ' . ' sonrası extension
        filename = filename.slice(0, lastDotIndex); // ' . ' öncesi filename
    }

    return {
        filename: filename,
        fileExtension: ext,
        url: baseUrl
    };


}



*/
