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

function decryptFile(encryptedFilePath, password) {
    const input = fs.createReadStream(encryptedFilePath);
    const orjinalPathData = returnPathAsArray(encryptedFilePath); // Dosya adını ve uzantısını almak için
    const outputFileName = `./decrypted/${orjinalPathData.filename}.${orjinalPathData.fileExtension}`;
    const output = fs.createWriteStream(outputFileName);

    return new Promise((resolve, reject) => {
        let header = Buffer.alloc(32); // Salt (16 bayt) + IV (16 bayt)
        let bytesRead = 0;
        let decipher;

        input.once("data", (chunk) => {
            // İlk 32 baytı okuyarak Salt ve IV'yi alıyoruz
            header = chunk.slice(0, 32);
            const salt = header.slice(0, 16);
            const iv = header.slice(16, 32);

            console.log("Çözülen Salt:", salt);
            console.log("Çözülen IV:", iv);

            // Derived Key oluşturuluyor
            const derivedKey = deriveKeyFromPassword(password, salt);
            console.log("Çözülen Key:", derivedKey);

            // Decipher akışı oluşturuluyor
            decipher = crypto.createDecipheriv("aes-256-cbc", derivedKey, iv);

            // Kalan chunk kısmını decipher akışına yazıyoruz
            const remainingChunk = chunk.slice(32);
            if (remainingChunk.length > 0) {
                decipher.write(remainingChunk);
            }

            // Tüm veri akışlarını bağlama
            input.pipe(decipher).pipe(output);
        });

        // Hata yönetimi
        input.on("error", reject);
        output.on("error", reject);
        output.on("finish", () => resolve(outputFileName));
    });
}

function encryptFile(inputPath, password) {
    const iv = crypto.randomBytes(16); // Rastgele IV oluşturma
    const salt = crypto.randomBytes(16); // Rastgele IV oluşturma
    const derivedKey = deriveKeyFromPassword(password, salt); // Şifreden anahtar türetme
    const cipher = crypto.createCipheriv("aes-256-cbc", derivedKey, iv);
    const orjinalPathData = returnPathAsArray(inputPath);
    // Dosyanın ismini SHA-256 ile hash'liyoruz (uzantısız)
    const encryptedFileName = generateFileNameFromHash(inputPath, iv);
    const encryptedFilePath =
        `./encrypted/${encryptedFileName}.` + orjinalPathData.fileExtension; // Şifreli dosyanın yolu (hash ile adlandırıyoruz)

    return new Promise((resolve, reject) => {
        const input = fs.createReadStream(inputPath);
        const output = fs.createWriteStream(encryptedFilePath);
        output.write(Buffer.concat([salt, iv]), (err) => {
            if (err) return reject(err);

            console.log("Salt:", salt);
            console.log("IV:", iv);
            console.log("Derived Key:", derivedKey);

            // Şifreleme işlemini başlatıyoruz
            const cipher = crypto.createCipheriv("aes-256-cbc", derivedKey, iv);
            input.pipe(cipher).pipe(output);

            // Akışların hata ve başarı yönetimi
            input.on("error", reject);
            cipher.on("error", reject);
            output.on("error", reject);
            output.on("finish", () => resolve(encryptedFilePath));
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
            "./encrypted/3430aa4b28ff9a201b917bbeb01df8453acba5cd49d3a08b8bd3267dbb87919f.JPEG",
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
