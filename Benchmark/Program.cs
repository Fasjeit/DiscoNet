using System;

namespace Benchmark
{
    using System.Linq;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;

    using BenchmarkDotNet.Attributes;
    using BenchmarkDotNet.Running;
    using DiscoNet;
    using DiscoNet.Net;
    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;

    [RPlotExporter, RankColumn]
    public class TheEasiestBenchmark
    {
        private SslStream sslClientStream;

        private TcpClient client;

        TcpListener tlsListener;

        Connection discoClient;
        //64, 128, 256, 512, 1024, 4094, 1048576
        [Params(1048576)]
        public int N;

        private byte[] dataC
        {
            get
            {
                var data = new byte[N];
                data[1] = 17;
                data[data.Length - 1] = 255;
                return data;
            }
        }

        [Benchmark(Description = "DiscoChannel")]
        public void DiscoChannel()
        {
            this.RunDiscoIteration();
        }

        [Benchmark(Description = "TlsStream")]
        public void TlsStream()
        {
            this.RunTestIterationTls();
        }

        private void PrepareTlsServer(int port)
        {
            this.tlsListener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
            this.tlsListener.Start();

            var serverCertificate = new X509Certificate2(
                @"localhost.pfx",
                "1");
            var server = Task.Factory.StartNew(
                () =>
                {
                    using (this.client = this.tlsListener.AcceptTcpClient())
                    {
                        using (var sslStream = new SslStream(this.client.GetStream(), false))
                        {
                            sslStream.AuthenticateAsServer(serverCertificate, false, SslProtocols.Tls, true);

                            while (true)
                            {
                                try
                                {
                                    var buf = new byte[100];
                                    byte lastByte = 0;
                                    do
                                    {
                                        var readByes = sslStream.Read(buf, 0, buf.Length);
                                        lastByte = buf[readByes - 1];
                                    }
                                    while (lastByte != 255);

                                    var data = dataC;
                                    sslStream.Write(data, 0, data.Length);
                                }
                                catch (System.IO.IOException)
                                {
                                    break;
                                }
                            }
                        }
                    }
                });
        }
      

        private void PrepareTlsClient(int port)
        {
            var client = new TcpClient("127.0.0.1", port);
            this.sslClientStream = new SslStream(
                client.GetStream(),
                false,
                new RemoteCertificateValidationCallback(ValidateServerCertificate),
                null);

                this.sslClientStream.AuthenticateAsClient("localhost");
        }

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        private void RunTestIterationTls()
        {
            var clienData = dataC;
            this.sslClientStream.Write(clienData, 0, clienData.Length);

            var bufClient = new byte[100];
            byte lastByte = 0;
            do
            {
                var readByes = sslClientStream.Read(bufClient, 0, bufClient.Length);
                lastByte = bufClient[readByes - 1];
            } while (lastByte != 255);
        }

        private void PrepareDisco(int port)
        {
            // init
            var clientConfig = new Config
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseNK
            };

            var serverConfig = new Config
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseNK
            };

            // set up remote keys
            serverConfig.RemoteKey = clientConfig.KeyPair.PublicKey;
            clientConfig.RemoteKey = serverConfig.KeyPair.PublicKey;
            this.PrepareDiscoServer(serverConfig, port);
            System.Threading.Thread.Sleep(5000);
            this.PrepareDiscoClient(clientConfig, port);

        }

        private void PrepareDiscoClient(Config clientConfig, int port)
        {
            var client = new TcpClient("127.0.0.1", port);
            this.discoClient = new Connection(client.GetStream(), clientConfig, true);

        }

        private void PrepareDiscoServer(Config serverConfig, int port)
        {
            this.tlsListener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
            this.tlsListener.Start();
            Task.Factory.StartNew(
                () =>
                {
                    using (this.client = this.tlsListener.AcceptTcpClient())
                    {
                        using (var listener = new Connection(this.client.GetStream(), serverConfig, false))
                        {
                            while (true)
                            {
                                try
                                {
                                    var buf = new byte[100];
                                    byte lastByte = 0;
                                    var iter = 0;
                                    do
                                    {
                                        iter++;
                                        var readByes = listener.Read(buf, 0, buf.Length);
                                        lastByte = buf[readByes - 1];
                                    }
                                    while (lastByte != 255);

                                    var data = dataC;
                                    listener.Write(data, 0, data.Length);
                                }
                                catch (Exception)
                                {
                                    break;
                                }
                            }
                        }
                        this.tlsListener.Stop();
                    }
                });
        }

        private void RunDiscoIteration()
        {
            {
                var clienData = dataC;
                discoClient.Write(clienData, 0, clienData.Length);

                var bufClient = new byte[100];
                byte lastByte = 0;
                do
                {
                    var readByes = discoClient.Read(bufClient, 0, bufClient.Length);
                    lastByte = bufClient[readByes - 1];
                } while (lastByte != 255);
            }
        }

        [GlobalCleanup]
        public void cleanUp()
        {
            this.client?.Dispose();
            this.sslClientStream?.Dispose();
            this.tlsListener?.Stop();
        }

        [GlobalSetup]
        public void Setup()
        {
            PrepareTlsServer(7775);
            PrepareTlsClient(7775);
            PrepareDisco(7774);
        }
    }



    class Program
    {

        static void Main(string[] args)
        {
            //var a = new TheEasiestBenchmark();
            //a.Setup();

            //for (int i = 0; i < 100000; i++)
            //{
            //    a.DiscoChannel();
            //    Console.WriteLine(i);
            //}

            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();
            //a.TlsStream();


            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();

            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();

            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();

            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();
            //a.DiscoChannel();


            //a.cleanUp();

            Console.WriteLine("Hello World!");
            BenchmarkRunner.Run<TheEasiestBenchmark>();
        }
    }
}
