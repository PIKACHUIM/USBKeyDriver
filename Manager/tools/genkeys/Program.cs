using System.Security.Cryptography;

// 一次性工具：生成开发用 RSA 密钥对，输出到控制台。
using var rsa = RSA.Create(2048);
var privateKey = rsa.ExportPkcs8PrivateKeyPem();
var publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
// 打印 PEM public 用于嵌入 Verifier
Console.WriteLine("=== PUBLIC (SubjectPublicKeyInfo base64) ===");
Console.WriteLine(publicKey);
Console.WriteLine();
Console.WriteLine("=== PRIVATE (PKCS8 PEM) ===");
Console.WriteLine(privateKey);
Console.WriteLine();
// 打印可嵌入字符串版本（去换行的base64）
var pubB64 = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()).Replace("+", "-").Replace("/", "_");
Console.WriteLine("=== PUBLIC embed (url-safe base64) ===");
Console.WriteLine(pubB64);
var privB64 = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
Console.WriteLine("=== PRIVATE embed (base64 single line) ===");
Console.WriteLine(privB64);
