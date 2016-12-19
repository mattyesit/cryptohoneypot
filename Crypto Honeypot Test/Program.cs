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


namespace Crypto_Honeypot
{
    class Program
    {
     
        // Reads file and looks for contents of settings
        [DllImport("kernel32")]
        private static extern int GetPrivateProfileString(string section, string key, string def, StringBuilder retVal, int size, string filePath);

        [DllImport("kernel32")]
        private static extern long WritePrivateProfileString(string section, string key, string val, string filePath);

        public const string ServiceName = "Crypto HoneyPot Service";
        public const string ServiceTitle = "cryptohoneypot";
        private static string honeypotName = "0_HoneyPot";
        private static bool alerted = false;
        private static string install;

        static void Main(string[] args)
        {
            Console.Title = "Crypto Honeypot";

            //  main program
            if (Environment.UserInteractive)
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
            Console.WriteLine("===========================================================");
            Console.WriteLine("####                                                   ####");
            Console.WriteLine("####        Cryptolocker Honeypot Configuration        ####");
            Console.WriteLine("####                                                   ####");
            Console.WriteLine("===========================================================\n");

            // Show menu options
            menuOptions();

            bool done = false;
            do
            {
                string selection = Console.ReadLine();
                int select;

                try
                {
                    select = int.Parse(selection);
                }
                catch
                {
                    Console.WriteLine("Incorrect");
                    select = 0;
                }
                Console.WriteLine("\n");
                switch (select)
                {
                    case 0:
                        Console.WriteLine("You selected an invalid number: {0}\r\n", select); 
                        break;
                    case 1:
                        // Install Service
                        installService();
                        // Show menu options again
                        menuOptions();
                        break;
                    case 2:
                        // Configure Honepots
                        configureHoneypot();
                        // Show menu options again
                        menuOptions();
                        break;
                    case 3:
                        done = true;
                        continue;
                    default:
                        break;

                }
            } while (!done);
        }

        public static void menuOptions()
        {
            Console.WriteLine("Please select an option from the menu:");
            Console.WriteLine("--------------------------\n");

            if (isServiceInstalled())
                install = "Uninstall";
            else
                install = "Install";


            Console.WriteLine("1 -- {0} Service", install);
            Console.WriteLine("2 -- Setup Honeypots");
            Console.WriteLine("3 -- Configure email notification");
            Console.WriteLine("4 -- Quit");

            Console.WriteLine("\nChoose and press enter: ");
        }

        public static void installService()
        {
            // Prepare CMD execution of SC to install/uninstall service
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd.exe";

            // Get path of current executable to install as service
            string path = Assembly.GetExecutingAssembly().Location;
            

            if (!DoesServiceExist(ServiceTitle, Environment.MachineName))
            {
                // Install service
                startInfo.Arguments = String.Format("/C sc create cryptohoneypot binPath= \"{0}\" displayName= \"{1}\" start= auto", path, ServiceName);
                process.StartInfo = startInfo;
                process.Start();

                // Give a second delay to install service else install/uninstall text will be incorrect
                Console.WriteLine("Installing...");
                System.Threading.Thread.Sleep(1000);
                Console.WriteLine("Service has been installed as: {0}\n", ServiceName);
            }
            else
            {
                // Stop service before removing
                startInfo.Arguments = @"/C sc stop cryptohoneypot";
                process.StartInfo = startInfo;
                process.Start();

                // Delete service
                startInfo.Arguments = @"/C sc delete cryptohoneypot";
                process.StartInfo = startInfo;
                process.Start();

                // Give a second delay to remove service else install/uninstall text will be incorrect
                Console.WriteLine("Uninstalling...");
                System.Threading.Thread.Sleep(1000);
                Console.WriteLine("Service {0} has been uninstalled!\n", ServiceName);
            }
        }

        public static bool isServiceInstalled()
        {
            // Check if service installed
            if (DoesServiceExist(ServiceTitle, Environment.MachineName))
                return true;
            return false;
        }

        public static void configureHoneypot()
        {
            // Get local PC's name and begin setup of honeypots
            string serverName = Environment.MachineName;
            Console.WriteLine("Setting up honeypot on {0}", serverName);
            Console.WriteLine("Choose shares to setup honeypot in. Type 'Y' & press enter to setup.");
            Console.WriteLine("--------------------------");
            // Get list of network shares on current PC
            List<string> shares = GetNetworkShareFoldersList(serverName);
            
            foreach (string share in shares)
            {
                string path = @"\\" + serverName + "\\" + share + "\\" + honeypotName;
                if (IsValidShare(share))
                {
                    if (!Directory.Exists(path))
                    {
                        Console.Write("Create honeypot in the share \"" + share + "\"? (Y): ");
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

            Console.WriteLine("\nRun as a service to begin monitoring\n");
            
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
        }


        /**
         *  Start services suppot
         */

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

        private static bool DoesServiceExist(string serviceName, string machineName)
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
