using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Net;

namespace PrimeEST
{
    class EstClient
    {
        static void Main(string[] args)
        {
            using (var webClient = new EstWebClient())
            {
                webClient.Proxy = null;

                // cacerts
                Console.WriteLine("------------------ cacerts ---------------------");
                var certificateChain = webClient.DownloadString("https://nautilus:8442/.well-known/est/staging/cacerts");
                Console.WriteLine(certificateChain);

                // simpleenroll
                Console.WriteLine("------------------ simpleenroll ---------------------");
                var keyPairGenerator = new RsaKeyPairGenerator();
                keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 2048));
                var keyPair = keyPairGenerator.GenerateKeyPair();
                var extensions = new Dictionary<DerObjectIdentifier, X509Extension>();
                var subjectAlternativeName = new GeneralName[] { new GeneralName(GeneralName.DnsName, System.Environment.MachineName ) };
                extensions.Add(X509Extensions.SubjectAlternativeName, new X509Extension(false, new DerOctetString(new GeneralNames(subjectAlternativeName))));
                Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest("SHA256withRSA",
                    new X509Name("CN=Windows Autoenrollment"),
                    keyPair.Public,
                    new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(new X509Extensions(extensions)))),
                    keyPair.Private);
                string base64Csr = Convert.ToBase64String(csr.GetDerEncoded());
                webClient.Headers["Content-Type"] = "application/pkcs10";
                webClient.Headers["Content-Transfer-Encoding"] = "base64";
                webClient.Credentials = new NetworkCredential("staging", "foo123");
                var certificate = webClient.UploadString("https://nautilus:8442/.well-known/est/staging/simpleenroll", base64Csr);
                Console.WriteLine(certificate);
            }

            Console.ReadLine();
        }
    }
}
