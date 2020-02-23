using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;

namespace PrimeEST
{
    class EstClient
    {
        static void Main(string[] args)
        {
            // Create event source, requires admin privileges
            using (EventLog eventLog = new EventLog("Application"))
            {
                eventLog.Source = "PrimeEST";
                eventLog.WriteEntry("Running EST Client.", EventLogEntryType.Information, 1);
            }

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
                extensions.Add(X509Extensions.SubjectAlternativeName, 
                    new X509Extension(false, new DerOctetString(new GeneralNames(subjectAlternativeName))));
                Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest("SHA256withRSA",
                    new X509Name("CN=Windows Autoenrollment"),
                    keyPair.Public,
                    new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(new X509Extensions(extensions)))),
                    keyPair.Private);
                var base64Csr = Convert.ToBase64String(csr.GetDerEncoded());
                webClient.Headers["Content-Type"] = "application/pkcs10";
                webClient.Headers["Content-Transfer-Encoding"] = "base64";
                webClient.Credentials = new NetworkCredential("staging", "foo123");
                var base64Certificate = webClient.UploadString("https://nautilus:8442/.well-known/est/staging/simpleenroll", base64Csr);
                Console.WriteLine(base64Certificate);

                var certificate = new X509CertificateParser().ReadCertificate(Convert.FromBase64String(base64Certificate));
                var keystore = new Pkcs12StoreBuilder()
                    .SetUseDerEncoding(true)
                    .Build();
                keystore.SetKeyEntry(Environment.MachineName, 
                    new AsymmetricKeyEntry(keyPair.Private), 
                    new X509CertificateEntry[] { new X509CertificateEntry(certificate) });
                byte[] pfxBytes = null;
                using (MemoryStream stream = new MemoryStream())
                {
                    keystore.Save(stream, "foo123".ToCharArray(), new SecureRandom());
                    pfxBytes = stream.ToArray();
                }


                X509Certificate2 cert = new X509Certificate2(Pkcs12Utilities.ConvertToDefiniteLength(pfxBytes), "foo123", X509KeyStorageFlags.PersistKeySet);
                X509Store store = new X509Store(StoreLocation.LocalMachine);
                // Requires program to run as administrator
                try
                {
                    store.Open(OpenFlags.ReadWrite);
                    store.Add(cert);
                } 
                catch (CryptographicException e)
                {
                    using (EventLog eventLog = new EventLog("Application"))
                    {
                        eventLog.Source = "PrimeEST";
                        eventLog.WriteEntry(e.Message, EventLogEntryType.Error, 2);
                    }
                }
            }

            Console.ReadLine();
        }
    }
}
