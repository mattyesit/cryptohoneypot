using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Reflection;
using System.Collections.Specialized;
using System.ServiceProcess;
using System.Timers;


namespace Crypto_Honeypot_Test
{
    class Program
    {
        private static string honeypotName = "0_HoneyPot";
        private static bool alerted = false;

        // Reads file and looks for contents of settings
        [DllImport("kernel32")]
        private static extern int GetPrivateProfileString(string section, string key, string def, StringBuilder retVal, int size, string filePath);

        [DllImport("kernel32")]
        private static extern long WritePrivateProfileString(string section, string key, string val, string filePath);

        public const string ServiceName = "Crypto HoneyPot Service";

        static void Main(string[] args)
        {
            //  main program
            if(Environment.UserInteractive)
                run();

            // Run main checks
            Timer RunTimer = new Timer();
            RunTimer.Elapsed += new ElapsedEventHandler(MonitorFolders);
            RunTimer.Interval = 500;
            RunTimer.Enabled = true;

            // Run as a service
            if (!Environment.UserInteractive)
            {
                // running as service
                using (var service = new Service())
                    ServiceBase.Run(service);
            }
            else
            {
                Console.WriteLine("Press q then enter to quit");
                while (Console.Read() != 'q') ;
            }
        }

        public class Service : ServiceBase
        {
            public Service()
            {
                ServiceName = Program.ServiceName;
            }

            protected override void OnStart(string[] args)
            {
                Start(args);
            }

            protected override void OnStop()
            {
                Stop();
            }
        }

        private static void Start(string[] args)
        {
            // onstart code here
        }

        private static void Stop()
        {
            // onstop code here
        }
        // End service

        public static void run()
        {
            Console.WriteLine("Enter Server Name:");
            string serverName = Console.ReadLine();
            Console.WriteLine("-------------");
            List<string> shares = GetNetworkShareFoldersList(serverName);

            //Dictionary<string, string> watchFiles = new Dictionary<string, string>;

            foreach (string share in shares)
            {
                string path = @"\\" + serverName + "\\" + share + "\\" + honeypotName;
                if (IsValidShare(share))
                {
                    if (!Directory.Exists(path))
                    {
                        Console.Write("Create folder in share " + share + " (Y): ");
                        string key = Console.ReadLine();
                        if (key == "Y" || key == "y")
                        {
                            CreateHoneyPotFolder(path);
                            Console.WriteLine("Created " + honeypotName + " in " + share);
                            Console.WriteLine("-----");
                            GenerateMonitorFiles(share, path);
                            Console.WriteLine("Successfully generated files to monitor in share");
                            Console.WriteLine("------------------------------------------------");
                        }
                    }

                }
            }

            IniWriteValue("Settings", "Server", serverName, getClientConfigFile());

            Console.WriteLine("Begin Monitoring");
            

            Console.ReadLine();
        }

        public static List<string> GetNetworkShareFoldersList(string serverName)
        {
            List<string> shares = new List<string>();

            // do not use ConnectionOptions to get shares from local machine
            ConnectionOptions connectionOptions = new ConnectionOptions();
            //connectionOptions.Username = @"Domain\Administrator";
            //connectionOptions.Password = "password";
            //connectionOptions.Impersonation = ImpersonationLevel.Impersonate;

            ManagementScope scope = new ManagementScope("\\\\" + serverName + "\\root\\CIMV2",
                                                        connectionOptions);
            scope.Connect();

            ManagementObjectSearcher worker = new ManagementObjectSearcher(scope,
                               new ObjectQuery("select Name from win32_share"));

            foreach (ManagementObject share in worker.Get())
            {
                shares.Add(share["Name"].ToString());
            }
            return shares;
        }

        public static Boolean IsValidShare(string share)
        {
            List<string> list = new List<string>();
            
            list.Add("C$");
            list.Add("D$");
            list.Add("E$");
            list.Add("F$");
            list.Add("G$");
            list.Add("H$");
            list.Add("I$");
            list.Add("J$");
            list.Add("K$");
            list.Add("L$");
            list.Add("M$");
            list.Add("N$");
            list.Add("O$");
            list.Add("P$");
            list.Add("Q$");
            list.Add("R$");
            list.Add("S$");
            list.Add("T$");
            list.Add("U$");
            list.Add("V$");
            list.Add("W$");
            list.Add("X$");
            list.Add("Y$");
            list.Add("Z$");
            list.Add("ADMIN$");
            list.Add("IPC$");

            if(list.Contains(share))
                return false;
            return true;
        }

        public static void CreateHoneyPotFolder(string path)
        {
            if (!Directory.Exists(path))
            {
                var folder = Directory.CreateDirectory(path);
            }
        }

        /**
         *  Copy files into honeypot folder
         */
        public static void GenerateMonitorFiles(string share, string path)
        {
            // Get Current executable path to see if files folder exists
            string currentPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string filesPath = currentPath + @"\files";
            // If directory exists then attempt copy of files to honeypot
            if(Directory.Exists(filesPath))
            {
                // Loop through files and check if they already exist in destination
                foreach (var file in Directory.GetFiles(filesPath))
                    if (!File.Exists(path + @"\" + Path.GetFileName(file)))
                    {
                        // Copy files to share
                        File.Copy(file, Path.Combine(path, Path.GetFileName(file)));
                        // Generate hash and add records to ini file
                        AddHashToConfig(share, path, file, GenerateHashes(Path.Combine(path, Path.GetFileName(file))));
                    }
            }
        }

        /*
        public static void GenerateHashesByPath(string path)
        {
            
            // Loop through path and generate hash
            foreach (var file in Directory.GetFiles(path))
                // Save hashes to config file
                AddHashToConfig(share, path, file, GenerateHashes(file));
        }
        */

        public static string GenerateHashes(string file)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    return BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "").ToLower();
                }
            }
        }


        public static void AddHashToConfig(string share, string path, string file, string hash)
        {
            // Get config file
            string strConfigFile = GetConfigFile();
            // Add file
            AddToConfig(strConfigFile, share, path, Path.GetFileName(file), hash);
        }

        public static string GetConfigFile(string config = null)
        {
            string strConfigFile = getClientConfigFile();

            if(!File.Exists(strConfigFile))
            {
                IniWriteValue("Settings", "Client", "YesIT", getClientConfigFile());
                IniWriteValue("Settings", "Code", "YIT", getClientConfigFile());
            }

            return strConfigFile;
        }

        public static void AddToConfig(string config, string share, string path, string file, string hash)
        {
            // Create Share as ini section with path as its first value even if it exists
            IniWriteValue(share, "path", path, config);
            // Add each file to share section with hash
            IniWriteValue(share, file, hash, config);

        }

        public static string getClientConfigFile()
        {
            return Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\CryptoWatcher.ini";
        }

        
        public static void MonitorFolders(object source, ElapsedEventArgs e)
        {
            string serverName = IniReadValue("Settings", "Server", getClientConfigFile());
            List<string> shares = GetNetworkShareFoldersList(serverName);

            foreach (string share in shares)
            {
                string path = @"\\" + serverName + "\\" + share + "\\" + honeypotName;
                if (IsValidShare(share))
                {
                    if (Directory.Exists(path))
                    {
                        foreach (var file in Directory.GetFiles(path))
                        {
                            // Get filename
                            string fileName = Path.GetFileName(file);
                            // Get has of current file
                            string hash = GenerateHashes(file);
                            // Get previous hash
                            string hashed = IniReadValue(share, fileName, getClientConfigFile());
                            // Compare hashes
                            if (hash != hashed)
                            {
                                if (alerted == false)
                                {
                                    // check if have alerted
                                    Console.WriteLine("Changed");
                                    StopService("Server", 1000);
                                }
                                // change alert to true to not piss people off
                                alerted = true;
                            }
                            
                        }
                    }

                }
            }

            /**
                Get share
                    Loop through files
                        Get hash of file
                        Compare hash of file to ini file

                        If changed stop server service
                     

             */
        }

        public static void StopService(string serviceName, int timeoutMilliseconds)
        {
            ServiceController service = new ServiceController(serviceName);
            try
            {
                TimeSpan timeout = TimeSpan.FromMilliseconds(timeoutMilliseconds);

                service.Stop();
                service.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
            }
            catch
            {
                // ...
            }
        }

        /**
         *  Start Supporting functions
         */

        // Reads settings file for value
        public static string IniReadValue(string Section, string Key, string path)
        {
            StringBuilder temp = new StringBuilder(255);
            int i = GetPrivateProfileString(Section, Key, "", temp, 255, path);
            return temp.ToString();
        }

        // Write to settings 
        public static void IniWriteValue(string Section, string Key, string Value, string path)
        {
            WritePrivateProfileString(Section, Key, Value, path);
        }

        // Check if key exists in array
        private static bool ContainsKey(NameValueCollection collection, string key)
        {
            if (collection.Get(key) == null)
                return collection.AllKeys.Contains(key);
            return true;
        }

        private bool DoesServiceExist(string serviceName, string machineName)
        {
            ServiceController[] services = ServiceController.GetServices(machineName);
            var service = services.FirstOrDefault(s => s.ServiceName == serviceName);
            return service != null;
        }

        /**
         *  End Supporting functions
         */

    }
}
