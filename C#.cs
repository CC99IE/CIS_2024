using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

class PKIExample
{
    static void Main()
    {
        Stopwatch stopwatch = new Stopwatch();
        stopwatch.Start();

        // Generate a RSA key pair
        using (RSA rsa = RSA.Create(2048))
        {
            // Create a self-signed certificate
            var request = new CertificateRequest("cn=TestCertificate", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

            // Convert certificate to a byte array and then back to a certificate
            // This step is just to mimic the process of storing and retrieving a certificate
            var certBytes = cert.Export(X509ContentType.Cert);
            var newCert = new X509Certificate2(certBytes);
        }

        stopwatch.Stop();

        // Calculate execution time in seconds
        double executionTime = stopwatch.Elapsed.TotalSeconds;

        // Throughput calculation (for one operation)
        double throughput = 1 / executionTime;

        Console.WriteLine($"Time taken: {executionTime} seconds");
        Console.WriteLine($"Throughput: {throughput} ops/s");
    }
}
