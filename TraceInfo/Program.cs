using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace TraceInfo
{
    class Program
    {
        /*
         * Scritto in modo frettoloso (ma pur sempre con amore) da Ivano Matrisciano
         * ivanomatrisciano@gmail.com
         * i.matrisciano@studenti.unina.it
         * 
         * Giugno 2020
         */
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                ShowHelp();
                return;
            }

            string fileCattura = args[0];
            if (!File.Exists(fileCattura))
            {
                Console.WriteLine("Il file " + fileCattura + " non esiste.");
                return;
            }


            int number_of_tcp_streams = -6;// per compensare l'overhead prima e dopo la tabella in output
            int number_of_udp_streams = -6;// per compensare l'overhead prima e dopo la tabella in output


            // NUMERO FLUSSI TCP

            Console.Write("Lettura numero di flussi TCP... ");
            Process proc = RunCmd("tshark", " -r " + fileCattura + " -q -z conv,tcp");
            while(proc.StandardOutput.ReadLine() != null)
                number_of_tcp_streams++;

            proc.Dispose();
            Console.WriteLine(number_of_tcp_streams + " flussi trovati");

            //NUMERO FLUSSI UDP

            Console.Write("Lettura numero di flussi UDP... ");
            proc = RunCmd("tshark", " -r " + fileCattura + " -q -z conv,udp");
            while (proc.StandardOutput.ReadLine() != null)
                number_of_udp_streams++;
            proc.Dispose();
            Console.WriteLine(number_of_udp_streams + " flussi trovati");


            List<Flusso> ListaFlussiTCP = new List<Flusso>(number_of_tcp_streams);
            List<Flusso> ListaFlussiUDP = new List<Flusso>(number_of_udp_streams);

            //GENERAZIONE OUTPUT PER I FLUSSI TCP

            
            for (int i = 0; i < number_of_tcp_streams; i++)
            {
                Console.Write("Lettura info flusso TCP " + (i + 1) + "/" + number_of_tcp_streams + "...");
                Flusso flusso = new Flusso();

                Thread thread0 = new Thread(() => {
                    proc = RunCmd("tshark", " -r " + fileCattura + " -q -z conv,tcp,\"tcp.stream == " + i + "\"");
                    //skippa 5 righe
                    for (int j = 0; j < 5; j++)
                        proc.StandardOutput.ReadLine();

                    string line = proc.StandardOutput.ReadLine();
                    proc.Dispose();
                    List<string> line_content = new List<string>(line.Split(' '));
                    line_content.RemoveAll(l => l.Length == 0 || l == "<->");

                    flusso.NumeroFlusso = i;
                    flusso.SourceAddrAndPort = line_content[0];
                    flusso.DestAddrAndPort = line_content[1];
                    flusso.nFramesIn = line_content[2];
                    flusso.bytesIn = line_content[3];
                    flusso.nFramesOut = line_content[4];
                    flusso.bytesOut = line_content[5];
                    flusso.nFramesTot = line_content[6];
                    flusso.bytesTot = line_content[7];
                    flusso.RelativeStart = line_content[8];
                    flusso.Duration = line_content[9];
                
                });
                
                

                //DNS
                Thread thread1 = new Thread( () => {
                    flusso.RisoluzioneDNS = GetOutput("tshark", "-r " + fileCattura + " -T fields -e frame.time_epoch -e frame.protocols -e dns.a -e dns.qry.name -Y \"(dns.flags.response == 1) && tcp.stream == " + i + "\"").Trim();
                });
                Thread thread2 = new Thread(() => {
                    flusso.SNI = GetOutput("tshark", "-r " + fileCattura + " -T fields -e ssl.handshake.extensions_server_name -Y \"tcp.stream == " + i + "\"").Trim();
                });
                Thread thread3 = new Thread(() =>{
                    flusso.HttpHost = GetOutput("tshark", "-r " + fileCattura + " -T fields -e http.host -Y \"tcp.stream == " + i + "\"").Trim();
                });
                thread0.Start();
                thread1.Start();
                thread2.Start();
                thread3.Start();
                thread0.Join();
                thread1.Join();
                thread2.Join();
                thread3.Join();

                ListaFlussiTCP.Add(flusso);
                Console.WriteLine(" OK");
            }


            for (int i = 0; i < number_of_udp_streams; i++)
            {
                Console.Write("Lettura info flusso UDP " + (i + 1) + "/" + number_of_udp_streams + "...");
                Flusso flusso = new Flusso();

                Thread thread0 = new Thread(() => {
                    proc = RunCmd("tshark", " -r " + fileCattura + " -q -z conv,udp,\"udp.stream == " + i + "\"");
                    //skippa 5 righe
                    for (int j = 0; j < 5; j++)
                        proc.StandardOutput.ReadLine();

                    string line = proc.StandardOutput.ReadLine();
                    proc.Dispose();
                    List<string> line_content = new List<string>(line.Split(' '));
                    line_content.RemoveAll(l => l.Length == 0 || l == "<->");

                    flusso.NumeroFlusso = i;
                    flusso.SourceAddrAndPort = line_content[0];
                    flusso.DestAddrAndPort = line_content[1];
                    flusso.nFramesIn = line_content[2];
                    flusso.bytesIn = line_content[3];
                    flusso.nFramesOut = line_content[4];
                    flusso.bytesOut = line_content[5];
                    flusso.nFramesTot = line_content[6];
                    flusso.bytesTot = line_content[7];
                    flusso.RelativeStart = line_content[8];
                    flusso.Duration = line_content[9];

                });

                //DNS
                Thread thread1 = new Thread(() => {
                    flusso.RisoluzioneDNS = GetOutput("tshark", "-r " + fileCattura + " -T fields -e frame.time_epoch -e frame.protocols -e dns.a -e dns.qry.name -Y \"(dns.flags.response == 1) && udp.stream == " + i + "\"").Trim();
                });
                Thread thread2 = new Thread(() => {
                    flusso.SNI = GetOutput("tshark", "-r " + fileCattura + " -T fields -e ssl.handshake.extensions_server_name -Y \"udp.stream == " + i + "\"").Trim();
                });
                Thread thread3 = new Thread(() => {
                    flusso.HttpHost = GetOutput("tshark", "-r " + fileCattura + " -T fields -e http.host -Y \"udp.stream == " + i + "\"").Trim();
                });
                thread0.Start();
                thread1.Start();
                thread2.Start();
                thread3.Start();
                thread0.Join();
                thread1.Join();
                thread2.Join();
                thread3.Join();

                ListaFlussiUDP.Add(flusso);
                Console.WriteLine(" OK");
            }


            const string header_tabella = "\"#\";\"Source Address\";\"Source Port\";\"Destination Address\";\"Destination Port\";\"n. Frames In\";\"Bytes In\";" +
                "\"n. Frames Out\";\"Bytes Out\";\"n. Frames Tot.\";\"Bytes Tot.\";\"Relative Start\";\"Duration\";\"Risoluzione DNS\";\"SNI\";\"HTTP Host\";";

            Console.Write("Generazione report analisi_tcp.csv...");
            StreamWriter writer = new StreamWriter("analisi_tcp.csv");
            writer.WriteLine(header_tabella);

            foreach (Flusso f in ListaFlussiTCP)
                writer.WriteLine(f.ToCSV());
            writer.Flush();
            writer.Close();
            Console.WriteLine(" OK");

            Console.Write("Generazione report analisi_udp.csv...");
            writer = new StreamWriter("analisi_udp.csv");
            writer.WriteLine(header_tabella);

            foreach (Flusso f in ListaFlussiUDP)
                writer.WriteLine(f.ToCSV());
            writer.Flush();
            writer.Close();
            Console.WriteLine(" OK");
        }



        static void ShowHelp()
        {
            Console.WriteLine("Usage: TraceInfo.exe <cattura.pcap>" +
                "\r\n Verranno generati i file analisi_tcp.csv e analisi_udp.csv");
        }

        static Process RunCmd(string program, string args)
        {
            Process proc = Process.Start(new ProcessStartInfo(program, args)
                {
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true
                });
            proc.WaitForExit();
            return proc;
        }
        static string GetOutput(string program, string args)
        {
            Process p = RunCmd(program, args);
            string output = p.StandardOutput.ReadToEnd();
            p.Dispose();
            return output;
        }
    }
}
