using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace TraceInfo
{
    class Flusso
    {
        public int NumeroFlusso;
        public string SourceAddrAndPort, DestAddrAndPort;
        public string SourceAddr
        {
            get { return SourceAddrAndPort.Split(':')[0]; }
        }
        public string SourcePort
        {
            get { return SourceAddrAndPort.Split(':')[1]; }
        }
        public string DestAddr
        {
            get { return DestAddrAndPort.Split(':')[0]; }
        }
        public string DestPort
        {
            get { return DestAddrAndPort.Split(':')[1]; }
        }
        public string nFramesIn, bytesIn, nFramesOut, bytesOut, nFramesTot, bytesTot;
        public string RelativeStart, Duration;



        public string RisoluzioneDNS, SNI, HttpHost;

        public string ToCSV()
        {

            StringBuilder b = new StringBuilder();
            void AggiungiCampo(string data, bool ultimo = false)
            {
                b.Append("\"" + data + "\"" + (ultimo ? "" : ";"));
            }

            AggiungiCampo(NumeroFlusso.ToString());
            AggiungiCampo(SourceAddr);
            AggiungiCampo(SourcePort);
            AggiungiCampo(DestAddr);
            AggiungiCampo(DestPort);
            AggiungiCampo(nFramesIn);
            AggiungiCampo(bytesIn);
            AggiungiCampo(nFramesOut);
            AggiungiCampo(bytesOut);
            AggiungiCampo(nFramesTot);
            AggiungiCampo(bytesTot);
            AggiungiCampo(RelativeStart);
            AggiungiCampo(Duration);
            AggiungiCampo(RisoluzioneDNS);
            AggiungiCampo(SNI);
            AggiungiCampo(HttpHost, true);

            return b.ToString();
        }

    }
}
