using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Remoting.Contexts;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace DU_Market_Release
{
    public class Program
    {

        public string curFile = "./config.xml";
        const string clientID = "1030935706538868746";
        const string clientSecret = "2CO0n3sHnNuDkkKBhikUfcllf0Nqaleq";
        const string authorizationEndpoint = "https://discord.com/api/oauth2/authorize";
        const string tokenEndpoint = "https://discord.com/api/oauth2/token";
        const string userInfoEndpoint = "https://discordapp.com/api/users/@me";
        public string new_access_token = "";
        public DateTime expiredate = DateTime.Now;
        bool durun = false;

        static void Main(string[] args)
        {
            //Check for Updates


            Program foo = new Program();
            foo.ProStart();
        }
        public void ProStart()
        { 


            if (!File.Exists(curFile))
            {
                Discord_login_data();

                while (new_access_token == "")
                {
                    Console.WriteLine("Warte auf Discord Login");
                    System.Threading.Thread.Sleep(1000);
                }


                new XDocument(
                    new XElement("root",
                        new XElement("access_token", new_access_token),
                        new XElement("expiredate", expiredate.ToString())
                        )
                    )
                    .Save(curFile);
            }
            else
            {
                Console.WriteLine("Read Config");

                FileStream fs = new FileStream(curFile, FileMode.Open, FileAccess.Read);
                XmlDocument xmldoc = new XmlDocument();

                xmldoc.Load(curFile);
                DateTime xmlexpire = DateTime.Parse(xmldoc.SelectSingleNode("/root/expiredate").InnerText);

                fs.Close();
                if (DateTime.Compare(DateTime.Now, xmlexpire) > 0)
                {

                    Discord_login_data();
                    while (new_access_token == "")
                    {
                        Console.WriteLine("Warte auf Discord Login");
                        System.Threading.Thread.Sleep(1000);
                    }
                    XmlDocument xmldoc2 = new XmlDocument();
                    xmldoc2.Load(curFile);
                    xmldoc2.SelectSingleNode("/root/access_token").InnerText = new_access_token;
                    xmldoc2.SelectSingleNode("/root/expiredate").InnerText = expiredate.ToString();
                    xmldoc2.Save(curFile);

                }
                else
                {
                    new_access_token = xmldoc.SelectSingleNode("/root/access_token").InnerText;
                }
            }


            string path;
            path = @"%localappdata%\NQ\DualUniverse\log\";
            path = Environment.ExpandEnvironmentVariables(path);
            
            while (true)
            { 
                
                while (!durun)
                {
                    Console.WriteLine("DU is not running.");
                    System.Threading.Thread.Sleep(3000);
                    durun = isDuRunning();
                }

                while(durun)
                { 
                Console.WriteLine("DU is running.");
                string logpath = GetLatestLog(path);
                string[] paths = { path, logpath };
                string fullpath = Path.Combine(paths);
                Console.WriteLine(logpath);
                ProcessFile(fullpath, new_access_token);
                durun = false;
                }

            }
            Console.ReadLine();
            return;
        }

        public static bool isDuRunning()
        {
            //Console.WriteLine("Check if DU is running.");
            Process[] pname = Process.GetProcessesByName("Dual");
            if (pname.Length == 0)
            {
                
                return false;
            }
            else
            {
                
                return true;
            }
        }
        private static string GetLatestLog(string path)
        {
            var file = new DirectoryInfo(path).GetFiles().OrderByDescending(o => o.LastWriteTime).FirstOrDefault();
            return file.Name;
        }
        public static async void ProcessFile(string fullPath, string access_token)
        {

        string UrlMarketstring = "";
        string Urlaverage = "";

        #if DEBUG
        {
            UrlMarketstring = "https://localhost:7153/marketapi/newdata";
                Urlaverage = "https://localhost:7153/marketapi/newaverage";
        }
#else
        {
            UrlMarketstring = "https://du-market.net/marketapi/newdata";
            Urlaverage = "https://du-market.net/marketapi/newaverage";
        }
#endif



            var wh = new AutoResetEvent(false);
            string exitphrase = "<message>Close \"dxgi.dll\"</message>";
            

            var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using (var sr = new StreamReader(fs))
            {

                var s = "";
                while (true)
                {
                    //Console.WriteLine(changed);
                    s = sr.ReadLine();
                    if (s != null)
                    {
                        //Console.WriteLine("---------------------------------");
                        //Console.WriteLine(s);

                        if (s.StartsWith("<message>Login Response"))
                        {

                        }
                        else if (s.StartsWith("<message>onUpdateMarketItemOrders:"))
                        {
                            
                            string cutstring = s.Remove(s.Length - 21);
                            if (cutstring.Length <= 58)
                            {
                                //return;
                                Console.WriteLine("null");
                            }
                            else { 
                                string cutstringe = cutstring.Remove(0, 59);
                                string[] orders;
                                orders = cutstringe.Split(new string[] { "MarketOrder:" }, StringSplitOptions.None);

                                List<string> numberssell = new List<string>();
                                List<string> numbersbuy = new List<string>();
                                Decimal maxbuyPrice = 0;
                                Decimal maxsellPrice = 0;
                                Decimal minbuyPrice = 0;
                                Decimal minsellPrice = 0;
                                long avitemtyp = 0;

                                foreach (string order in orders)
                                {
                                    if(order.Length != 0)
                                    { 
                                        
                                        MarketString marketData = new MarketString();
                                        string marketId1 = order.Remove(0, 12);
                                        string marketId2 = marketId1.Substring(0, marketId1.IndexOf(", orderId"));
                                        marketData.marketId = int.Parse(marketId2);

                                        string orderId1 = order.Substring(order.IndexOf("orderId = ") + 10);
                                        string orderId2 = orderId1.Substring(0, orderId1.IndexOf(", itemType"));
                                        marketData.orderid = long.Parse(orderId2);

                                        string itemtype1 = order.Substring(order.IndexOf(", itemType = ") + 13);
                                        string itemtype2 = itemtype1.Substring(0, itemtype1.IndexOf(", buyQuantity"));
                                        marketData.itemtyp = long.Parse(itemtype2);

                                        string buyquantity1 = order.Substring(order.IndexOf(", buyQuantity = ") + 16);
                                        string buyquantity2 = buyquantity1.Substring(0, buyquantity1.IndexOf(", expirationDate"));
                                        marketData.quantity = Convert.ToInt64(buyquantity2);

                                        string expdate1 = order.Substring(order.IndexOf("expirationDate = ") + 34);
                                        string expdate2 = expdate1.Substring(0, expdate1.IndexOf(", updateDate"));
                                        marketData.expirationDate = Convert.ToDateTime(expdate2);

                                        string updatedate1 = order.Substring(order.IndexOf("updateDate = @") + 30);
                                        string updatedate2 = updatedate1.Substring(0, updatedate1.IndexOf(", unitPrice ="));
                                        marketData.updatedate = Convert.ToDateTime(updatedate2);

                                        string price1 = order.Substring(order.IndexOf("amount = ") + 9);
                                        string price2 = "";
                                        if (price1.Contains("]],"))
                                        {
                                            price2 = price1.Substring(0, price1.IndexOf("]],"));
                                        }
                                        else
                                        {
                                            price2 = price1.Substring(0, price1.IndexOf("]]"));
                                        }
                                        if (price2.Length < 3)
                                        {
                                            price2 = "00" + price2;
                                        }
                                        else
                                        {

                                        }

                                        string price3 = price2.Insert(price2.Length - 2, ".");
                                        marketData.price = Convert.ToDecimal(price3.Replace(".", ","));
                                        if(marketData.quantity > 0)//BuyOrders
                                        {
                                            if(marketData.price > 10)
                                            {
                                                numbersbuy.Add(price3);
                                            }
                                            
                                            if(marketData.price > maxbuyPrice)
                                            {
                                                maxbuyPrice = marketData.price;
                                            }
                                            else if(marketData.price < minbuyPrice | minbuyPrice == 0)
                                            {
                                                minbuyPrice = marketData.price;
                                            }
                                        }
                                        else
                                        {
                                            if (marketData.price > 10)
                                            {
                                                numberssell.Add(price3);
                                            }
                                            if(marketData.price > maxsellPrice)
                                            {
                                                maxsellPrice = marketData.price;
                                            }
                                            else if(marketData.price < minsellPrice | minsellPrice == 0)
                                            {
                                                minsellPrice = marketData.price;
                                            }
                                        }

                                        marketData.date = DateTime.Now;
                                        avitemtyp = marketData.itemtyp;

                                        if (marketData.expirationDate < DateTime.Now)
                                        { }
                                        else
                                        {
                                            
                                            HttpClient httpClient = new HttpClient();
                                            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                                            httpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + access_token);

                                            var content = new StringContent(JsonConvert.SerializeObject(marketData), Encoding.UTF8, "application/json");
                                            var result = httpClient.PostAsync(UrlMarketstring, content).Result;

                                            if (!result.IsSuccessStatusCode)
                                            {
                                                Console.WriteLine(result.StatusCode);
                                            }

                                        }


                                    }

                                }
                                Market_Average Average = new Market_Average();
                                Average.itemtyp = avitemtyp;
                                Average.Actdate = DateTime.Now;
                                Average.minbuyPrice = minbuyPrice;
                                Average.maxbuyPrice = maxbuyPrice;
                                Average.minsellPrice = minsellPrice;
                                Average.maxsellPrice = maxsellPrice;
                                if(numbersbuy.Count != 0)
                                {
                                    Average.averagebuyPrice = Convert.ToDecimal(numbersbuy.Average(num => decimal.Parse(num)));
                                }
                                else
                                {
                                    Average.averagebuyPrice = 0;
                                }
                                if(numberssell.Count != 0)
                                {
                                    Average.averagesellPrice = Convert.ToDecimal(numberssell.Average(num => decimal.Parse(num)));
                                }
                                else
                                {
                                    Average.averagesellPrice = 0;
                                }
                                

                                HttpClient httpClient2 = new HttpClient();
                                httpClient2.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                                httpClient2.DefaultRequestHeaders.Add("Authorization", "Bearer " + access_token);

                                var content2 = new StringContent(JsonConvert.SerializeObject(Average), Encoding.UTF8, "application/json");
                                var result2 = httpClient2.PostAsync(Urlaverage, content2).Result;

                                Console.WriteLine("Send Done");
                            }


                        }
                        else if (s.StartsWith(exitphrase))
                        {
                            Console.WriteLine("Du Stopped");
                            return;
                        }
                        else
                        {

                        }
                    }


                    else
                    { 
                        wh.WaitOne(0);
                    }
                }
                wh.Close();
            }

        }
    

    /*
    public static Task<string> MarketSendApiAsync(string sendtoapi)
    {
        Console.WriteLine("api");
        //Console.WriteLine(sendtoapi);

        var httpClient = new HttpClient();
        var client = new swaggerClient("https://api.du-market.net", httpClient);
        //var client = new swaggerClient("https://localhost:7250/", httpClient);

        client.SetAsync(sendtoapi);
        Console.WriteLine(sendtoapi);

        return Task.FromResult("ok");

    }
    */
        public async void Discord_login_data()
        {
            // Generates state and PKCE values.
            string state = randomDataBase64url(32);
            string code_verifier = randomDataBase64url(32);
            string code_challenge = base64urlencodeNoPadding(sha256(code_verifier));
            const string code_challenge_method = "S256";

            const string authorizationEndpoint = "https://discord.com/api/oauth2/authorize";
            const string tokenEndpoint = "https://discord.com/api/oauth2/token";
            const string userInfoEndpoint = "https://discordapp.com/api/users/@me";

            // Creates a redirect URI using an available port on the loopback address.
            string redirectURI = string.Format("http://{0}:{1}/", IPAddress.Loopback, 58224);
            Console.WriteLine("redirect URI: " + redirectURI);

            // Creates an HttpListener to listen for requests on that redirect URI.
            var http = new HttpListener();
            http.Prefixes.Add(redirectURI);
            Console.WriteLine("Listening..");
            http.Start();

            // Creates the OAuth 2.0 authorization request.
            string authorizationRequest = string.Format("{0}?client_id={2}&redirect_uri={1}&response_type=code&scope=guilds%20identify%20guilds.members.read",
                        authorizationEndpoint,
                        System.Uri.EscapeDataString(redirectURI),
                        clientID,
                        state,
                        code_challenge,
                        code_challenge_method);

            // Opens request in the browser.
            //System.Diagnostics.Process.Start(authorizationRequest);
            Process.Start(new ProcessStartInfo(authorizationRequest) { UseShellExecute = true });

            // Waits for the OAuth authorization response.
            var context = await http.GetContextAsync();

            // Sends an HTTP response to the browser.
            var response = context.Response;
            string responseString = string.Format("<html><head><meta http-equiv='refresh' content='5;url=https://google.com'></head><body>Please return to the app.</body></html>");
            var buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            var responseOutput = response.OutputStream;
            Task responseTask = responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith((task) =>
            {
                responseOutput.Close();
                http.Stop();
                Console.WriteLine("HTTP server stopped.");

            });

            // Checks for errors.
            if (context.Request.QueryString.Get("error") != null)
            {
                Console.WriteLine(String.Format("OAuth authorization error: {0}.", context.Request.QueryString.Get("error")));
                return;
            }

            // extracts the code
            var codetrim = context.Request.RawUrl;
            var code = codetrim.Substring(7);
            var incoming_state = context.Request.QueryString.Get("state");

            // Compares the receieved state to the expected value, to ensure that
            // this app made the request which resulted in authorization.
            /*if (incoming_state != state)
            {
                output(String.Format("Received request with invalid state ({0})", incoming_state));
                return;
            }*/
            Console.WriteLine("Authorization code: " + code);
            // Starts the code exchange at the Token Endpoint.
            performCodeExchange(code, code_verifier, redirectURI);
            return;

        }

        async void performCodeExchange(string code, string code_verifier, string redirectURI)
        {
            Console.WriteLine("Exchanging code for tokens...");

            // builds the  request
            string tokenRequestURI = "https://discord.com/api/oauth2/token";
            string tokenRequestBody = string.Format("client_id={2}&grant_type=authorization_code&code={0}&redirect_uri={1}&client_secret={4}",
                        code,
                        System.Uri.EscapeDataString(redirectURI),
                        clientID,
                        code_verifier,
                        clientSecret
                        );

            // sends the request
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(tokenRequestURI);
            tokenRequest.Method = "POST";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
            tokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = tokenRequest.GetRequestStream();
            await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            WebResponse response2 = tokenRequest.GetResponse();
            stream = response2.GetResponseStream();

            StreamReader reader2 = new StreamReader(stream);
            string responseFromServer = reader2.ReadToEnd();

            var responsediscord = JsonConvert.DeserializeObject<Discord_Access_response>(responseFromServer);


            new_access_token = responsediscord.access_token;
            DateTime actdate = DateTime.Now;
            expiredate = actdate.AddSeconds(Convert.ToDouble(responsediscord.expires_in));

            Discord_login_data accresponse = new Discord_login_data();
            accresponse.access_token = new_access_token;
            accresponse.expires_date = expiredate;
            //return accresponse;

        }

        static string randomDataBase64url(uint length)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return base64urlencodeNoPadding(bytes);
        }

        /// <summary>
        /// Returns the SHA256 hash of the input string.
        /// </summary>
        /// <param name="inputStirng"></param>
        /// <returns></returns>
        static byte[] sha256(string inputStirng)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(inputStirng);
            SHA256Managed sha256 = new SHA256Managed();
            return sha256.ComputeHash(bytes);
        }

        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        static string base64urlencodeNoPadding(byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }

        
    }

}
