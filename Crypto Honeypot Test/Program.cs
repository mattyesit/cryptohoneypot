using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Reflection;
using System.Xml.Linq;
using System.Collections.Specialized;
using System.ServiceProcess;

namespace Crypto_Honeypot_Test
{
    class Program
    {
        private static string BaselineHash;
        private static string honeypotName = "0_HoneyPot";

        // Reads file and looks for contents of settings
        [DllImport("kernel32")]
        private static extern int GetPrivateProfileString(string section, string key, string def, StringBuilder retVal, int size, string filePath);

        [DllImport("kernel32")]
        private static extern long WritePrivateProfileString(string section, string key, string val, string filePath);

        static void Main(string[] args)
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
                    if (!Directory.Exists(share))
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
                            //GenerateMonitorFiles(share, path);
                        }
                    }

                }
            }
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

        /*
        public static void MonitorFolders(string path)
        {
            Watchers = new List<FileSystemWatcher>();

            //Store hash of baseline
            using (var md5 = MD5.Create())
            {
                using (Stream baseline = Assembly.GetExecutingAssembly().GetManifestResourceStream("CryptoWatcher.Resources.Baseline.doc"))
                {
                    BaselineHash = BitConverter.ToString(md5.ComputeHash(baseline)).Replace("-", "").ToLower();
                }
            }

            foreach (var folder in Config.Element("root").Descendants("folder"))
            {
                string strPath = folder.Element("path").Value;
                string strTestPath = strPath + "\\DO NOT EDIT THIS DOCUMENT.doc";
                Console.WriteLine("Setting up path: " + strPath);

                //Check if the resource file is there
                if (!File.Exists(strTestPath))
                {
                    File.WriteAllBytes(strTestPath, CryptoWatcher.Properties.Resources.Baseline);
                    Console.WriteLine("Baseline copied to {0}", strTestPath);
                }

                //Now compare the existing with our stored to make sure baseline is a match
                if (BaselineHash != GetHash(strTestPath))
                {
                    //Files already don't match, quit out and suggest deleting
                    Console.WriteLine("Test file {0} doesn't match baseline, delete and allow to be replaced", strTestPath);
                    Environment.Exit(1);
                }

                //Now set up watcher on this file
                FileSystemWatcher watcher = new FileSystemWatcher();
                watcher.Path = Path.GetDirectoryName(strTestPath);
                watcher.IncludeSubdirectories = false;
                watcher.Filter = Path.GetFileName(strTestPath);
                watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.LastAccess | NotifyFilters.Size | NotifyFilters.Security;
                watcher.Changed += watcher_Changed;
                watcher.EnableRaisingEvents = true;
                Watchers.Add(watcher);
            }

            Console.ReadKey(true);
        }
        */

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
