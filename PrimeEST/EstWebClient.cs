using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace PrimeEST
{
    internal class EstWebClient : WebClient
    {
        public X509Certificate2 ClientCertificate { private get; set; }

        protected override WebRequest GetWebRequest(Uri address)
        {
            HttpWebRequest request = (HttpWebRequest)base.GetWebRequest(address);
            ServicePointManager.ServerCertificateValidationCallback = delegate (object obj, X509Certificate serverCertificate, X509Chain chain, SslPolicyErrors errors)
            {
                // TODO Allow everything for now
                return true;
            };
            if (ClientCertificate != null)
            {
                request.ClientCertificates.Add(ClientCertificate);
            }
            return request;
        }
    }
}