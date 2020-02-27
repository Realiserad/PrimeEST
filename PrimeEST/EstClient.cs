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
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
                ServicePointManager.Expect100Continue = true;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                // cacerts
                Console.WriteLine("------------------ cacerts ---------------------");
                var base64CertificateChain = webClient.DownloadString("https://nautilus:8442/.well-known/est/staging/cacerts");
                Console.WriteLine(base64CertificateChain);
                var certificateChain = new X509Certificate2Collection();
                certificateChain.Import(Convert.FromBase64String(base64CertificateChain));

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
                    store.Close();
                } 
                catch (CryptographicException e)
                {
                    using (EventLog eventLog = new EventLog("Application"))
                    {
                        eventLog.Source = "PrimeEST";
                        eventLog.WriteEntry(e.Message, EventLogEntryType.Error, 2);
                    }
                }

                // simpleenroll
                Console.WriteLine("------------------ simplereenroll ---------------------");
                X509Certificate2 issuer = certificateChain[certificateChain.Count - 1];
                var storeToSearch = new X509Store(StoreLocation.LocalMachine);
                storeToSearch.Open(OpenFlags.ReadOnly);
                var certificates = storeToSearch.Certificates.Find(X509FindType.FindByIssuerDistinguishedName, issuer.Subject, false);
                Console.WriteLine("Found: " + certificates.Count);
                foreach (X509Certificate2 certificateToRenew in certificates) {
                    // Renew 10 years before expiry, i.e. always renew for testing purposes
                    bool isAboutToExpire = DateTime.Now + TimeSpan.FromDays(3650) > certificateToRenew.NotAfter;
                    if (!isAboutToExpire)
                    {
                        Console.WriteLine("Not renewing " + certificateToRenew.Subject + ". The certificate does not expire yet...");
                        continue;
                    }

                    Console.WriteLine("Trying to renew certificate: " + certificateToRenew.Subject);

                    //var keyPairGenerator = new RsaKeyPairGenerator();
                    //keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 2048));
                    keyPair = keyPairGenerator.GenerateKeyPair();
                    extensions = new Dictionary<DerObjectIdentifier, X509Extension>();
                    var subjectAlternativeName2 = new GeneralName[] { new GeneralName(GeneralName.DnsName, System.Environment.MachineName) };
                    extensions.Add(X509Extensions.SubjectAlternativeName,
                        new X509Extension(false, new DerOctetString(new GeneralNames(subjectAlternativeName))));
                    csr = new Pkcs10CertificationRequest("SHA256withRSA",
                        new X509Name("CN=Windows Autoenrollment"),
                        keyPair.Public,
                        new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(new X509Extensions(extensions)))),
                        keyPair.Private);
                    base64Csr = Convert.ToBase64String(csr.GetDerEncoded());
                    webClient.Headers["Content-Type"] = "application/pkcs10";
                    webClient.Headers["Content-Transfer-Encoding"] = "base64";
                    webClient.ClientCertificate = certificateToRenew;
                    Console.WriteLine("Do we have a private key? " + certificateToRenew.HasPrivateKey);
                    //var renewedBase64Certificate = webClient.UploadString("https://nautilus:8443/.well-known/est/staging/simplereenroll", base64Csr);
                    string renewedBase64Certificate = null;
                    var clientHandler = new HttpClientHandler();
                    clientHandler.ClientCertificates.Add(certificateToRenew);
                    clientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                    using (var httpClient = new HttpClient(clientHandler))
                    {
                        using (var request = new HttpRequestMessage(new HttpMethod("POST"), "https://nautilus:8443/.well-known/est/staging/simplereenroll"))
                        {
                            request.Headers.TryAddWithoutValidation("Content-Transfer-Encoding", "base64");
                            request.Content = new StringContent(base64Csr);
                            request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/pkcs10");
                            var response = httpClient.SendAsync(request).Result;
                        }
                    }

                    Console.WriteLine(base64Certificate);

                    var renewedCertificate = new X509CertificateParser().ReadCertificate(Convert.FromBase64String(renewedBase64Certificate));
                    keystore = new Pkcs12StoreBuilder()
                        .SetUseDerEncoding(true)
                        .Build();
                    keystore.SetKeyEntry(Environment.MachineName,
                        new AsymmetricKeyEntry(keyPair.Private),
                        new X509CertificateEntry[] { new X509CertificateEntry(renewedCertificate) });
                    pfxBytes = null;
                    using (MemoryStream stream = new MemoryStream())
                    {
                        keystore.Save(stream, "foo123".ToCharArray(), new SecureRandom());
                        pfxBytes = stream.ToArray();
                    }


                    cert = new X509Certificate2(Pkcs12Utilities.ConvertToDefiniteLength(pfxBytes), "foo123", X509KeyStorageFlags.PersistKeySet);
                    // Requires program to run as administrator
                    try
                    {
                        store.Open(OpenFlags.ReadWrite);
                        store.Add(cert);
                        store.Close();
                    }
                    catch (CryptographicException e)
                    {
                        using (EventLog eventLog = new EventLog("Application"))
                        {
                            eventLog.Source = "PrimeEST";
                            eventLog.WriteEntry(e.Message, EventLogEntryType.Error, 2);
                        }
                    }

                    // TODO Remove old cert
                }
            }

            Console.ReadLine();
        }
    }
}
