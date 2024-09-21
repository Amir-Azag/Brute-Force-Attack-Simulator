using System;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

// Add these namespaces for bcrypt and argon2
using BCrypt.Net;
using Isopoh.Cryptography.Argon2;

namespace PasswordCracker
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Password Cracker Simulation\n");

            // Prompt user for options
            Console.WriteLine("Choose hashing algorithm (md5/sha256/bcrypt/argon2):");
            string hashAlgorithm = Console.ReadLine().ToLower();

            // Validate hashing algorithm
            if (hashAlgorithm != "md5" && hashAlgorithm != "sha256" && hashAlgorithm != "bcrypt" && hashAlgorithm != "argon2")
            {
                Console.WriteLine("Invalid algorithm selected. Defaulting to sha256.");
                hashAlgorithm = "sha256";
            }

            Console.WriteLine("Use salting? (yes/no):");
            string useSaltingInput = Console.ReadLine().ToLower();
            bool useSalting = useSaltingInput == "yes";

            Console.WriteLine("Enable multi-threading? (yes/no):");
            string useMultithreadingInput = Console.ReadLine().ToLower();
            bool useMultithreading = useMultithreadingInput == "yes";

            Console.WriteLine("Choose character set: ");
            Console.WriteLine("1. Numeric (0-9)");
            Console.WriteLine("2. Lowercase letters (a-z)");
            Console.WriteLine("3. Uppercase letters (A-Z)");
            Console.WriteLine("4. Alphanumeric (0-9, a-z, A-Z)");
            Console.WriteLine("5. All printable ASCII characters");
            Console.Write("Enter option number: ");
            int charsetOption = int.Parse(Console.ReadLine());

            char[] charSet = GetCharacterSet(charsetOption);

            Console.WriteLine("Do you want to use a custom password? (yes/no):");
            string useCustomPasswordInput = Console.ReadLine().ToLower();
            bool useCustomPassword = useCustomPasswordInput == "yes";

            if (useCustomPassword)
            {
                Console.Write("Enter your custom password: ");
                string customPassword = Console.ReadLine();

                // Salting setup
                string salt = "";
                if (useSalting && (hashAlgorithm == "md5" || hashAlgorithm == "sha256"))
                {
                    // Generate a random salt
                    salt = GenerateRandomSalt();
                    Console.WriteLine($"Using salt: {salt}");
                }

                // Hash the custom password
                string passwordHash = HashPassword(customPassword, hashAlgorithm, salt);

                Console.WriteLine($"Your password hash: {passwordHash}");

                // Determine max password length for brute-force attack
                Console.Write("Enter maximum password length to attempt (e.g., 4, 6, 8): ");
                int maxPasswordLength = int.Parse(Console.ReadLine());

                // Start brute-force attack
                Console.WriteLine("\nStarting brute-force attack...");

                var result = RunBruteForceAttack(passwordHash, customPassword.Length, hashAlgorithm, useMultithreading, charSet, salt);

                if (result.crackedPassword != null)
                {
                    Console.WriteLine($"Password '{result.crackedPassword}' cracked in {result.attempts:N0} attempts and {result.timeTaken:F2} seconds.");
                }
                else
                {
                    Console.WriteLine("Password not cracked.");
                }
            }
            else
            {
                // Run predefined simulations
                RunCombinedSimulation(hashAlgorithm, useSalting, useMultithreading, charSet);
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        // Function to get character set based on user selection
        static char[] GetCharacterSet(int option)
        {
            switch (option)
            {
                case 1:
                    return "0123456789".ToCharArray();
                case 2:
                    return "abcdefghijklmnopqrstuvwxyz".ToCharArray();
                case 3:
                    return "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
                case 4:
                    return "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
                case 5:
                    return Enumerable.Range(32, 95).Select(i => (char)i).ToArray(); // All printable ASCII characters
                default:
                    Console.WriteLine("Invalid option selected. Defaulting to numeric characters.");
                    return "0123456789".ToCharArray();
            }
        }

        // Function to hash the password
        public static string HashPassword(string password, string algorithm = "sha256", string salt = "")
        {
            if (algorithm == "md5")
            {
                using (MD5 md5 = MD5.Create())
                {
                    byte[] inputBytes = Encoding.ASCII.GetBytes(salt + password);
                    byte[] hashBytes = md5.ComputeHash(inputBytes);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
            else if (algorithm == "sha256")
            {
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] inputBytes = Encoding.ASCII.GetBytes(salt + password);
                    byte[] hashBytes = sha256.ComputeHash(inputBytes);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
            else if (algorithm == "bcrypt")
            {
                return BCrypt.Net.BCrypt.HashPassword(password);
            }
            else if (algorithm == "argon2")
            {
                return Argon2.Hash(password);
            }
            else
            {
                throw new ArgumentException("Unsupported hashing algorithm");
            }
        }

        // Function to verify the password hash
        public static bool VerifyPassword(string attemptPassword, string hashedPassword, string algorithm = "sha256", string salt = "")
        {
            if (algorithm == "md5" || algorithm == "sha256")
            {
                string attemptHash = HashPassword(attemptPassword, algorithm, salt);
                return attemptHash == hashedPassword;
            }
            else if (algorithm == "bcrypt")
            {
                return BCrypt.Net.BCrypt.Verify(attemptPassword, hashedPassword);
            }
            else if (algorithm == "argon2")
            {
                return Argon2.Verify(hashedPassword, attemptPassword);
            }
            else
            {
                throw new ArgumentException("Unsupported hashing algorithm");
            }
        }

        // Function to run brute-force attack
        public static (int attempts, double timeTaken, string crackedPassword) RunBruteForceAttack(string targetPasswordHash, int maxLength, string hashAlgorithm, bool useMultithreading, char[] charSet, string salt)
        {
            if (useMultithreading)
            {
                return BruteForceAttackMultiThreaded(targetPasswordHash, maxLength, hashAlgorithm, charSet, salt);
            }
            else
            {
                return BruteForceAttack(targetPasswordHash, maxLength, hashAlgorithm, charSet, salt);
            }
        }

        // Multi-threaded brute-force attack
        public static (int attempts, double timeTaken, string crackedPassword) BruteForceAttackMultiThreaded(string targetPasswordHash, int maxLength, string hashAlgorithm = "sha256", char[] charSet = null, string salt = "")
        {
            if (charSet == null)
            {
                charSet = "0123456789".ToCharArray();
            }

            int attempts = 0;
            bool passwordFound = false;
            string crackedPassword = null;
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            // Use Parallel.For for multithreading
            ParallelOptions parallelOptions = new ParallelOptions();
            parallelOptions.MaxDegreeOfParallelism = Environment.ProcessorCount;

            try
            {
                Parallel.For(1, maxLength + 1, parallelOptions, (currentLength, state) =>
                {
                    var totalCombinations = (long)Math.Pow(charSet.Length, currentLength);
                    for (long i = 0; i < totalCombinations; i++)
                    {
                        if (passwordFound)
                        {
                            state.Stop();
                            break;
                        }

                        Interlocked.Increment(ref attempts);
                        string attemptPassword = IndexToPassword(i, currentLength, charSet);

                        if (VerifyPassword(attemptPassword, targetPasswordHash, hashAlgorithm, salt))
                        {
                            crackedPassword = attemptPassword;
                            passwordFound = true;
                            state.Stop();
                            break;
                        }

                        if (attempts % 1000000 == 0)
                        {
                            Console.WriteLine($"Attempts so far: {attempts:N0}");
                        }
                    }
                });
            }
            catch (OperationCanceledException)
            {
                // Ignore cancellation exception
            }

            stopwatch.Stop();

            return (attempts, stopwatch.Elapsed.TotalSeconds, crackedPassword);
        }

        // Single-threaded brute-force attack
        public static (int attempts, double timeTaken, string crackedPassword) BruteForceAttack(string targetPasswordHash, int maxLength, string hashAlgorithm = "sha256", char[] charSet = null, string salt = "")
        {
            if (charSet == null)
            {
                charSet = "0123456789".ToCharArray();
            }

            int attempts = 0;
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            for (int currentLength = 1; currentLength <= maxLength; currentLength++)
            {
                var totalCombinations = (long)Math.Pow(charSet.Length, currentLength);
                for (long i = 0; i < totalCombinations; i++)
                {
                    attempts++;
                    string attemptPassword = IndexToPassword(i, currentLength, charSet);

                    if (VerifyPassword(attemptPassword, targetPasswordHash, hashAlgorithm, salt))
                    {
                        stopwatch.Stop();
                        return (attempts, stopwatch.Elapsed.TotalSeconds, attemptPassword);
                    }

                    if (attempts % 1000000 == 0)
                    {
                        Console.WriteLine($"Attempts so far: {attempts:N0}");
                    }
                }
            }

            stopwatch.Stop();
            return (attempts, stopwatch.Elapsed.TotalSeconds, null);
        }

        // Converts an index to a password string based on the character set
        public static string IndexToPassword(long index, int length, char[] charSet)
        {
            char[] password = new char[length];
            int charSetLength = charSet.Length;

            for (int i = length - 1; i >= 0; i--)
            {
                password[i] = charSet[(int)(index % charSetLength)];
                index /= charSetLength;
            }

            return new string(password);
        }

        // Function to run the brute-force simulation with predefined passwords
        public static void RunCombinedSimulation(string hashAlgorithm, bool useSalting, bool useMultithreading, char[] charSet)
        {
            // Lists of passwords
            List<string> easyPasswords = new List<string> { "1234", "9876", "4321", "0000", "5555" }; // 4 digits
            List<string> mediumPasswords = new List<string> { "123456", "654321", "112233", "000000", "999999" }; // 6 digits
            List<string> difficultPasswords = new List<string> { "12345678", "87654321", "11223344", "00001111", "98765432" }; // 8 digits

            // Collect results for analysis
            List<(string difficulty, string password, int attempts, double timeTaken)> results = new List<(string, string, int, double)>();

            // Salting setup
            string salt = "";
            if (useSalting && (hashAlgorithm == "md5" || hashAlgorithm == "sha256"))
            {
                // Generate a random salt
                salt = GenerateRandomSalt();
                Console.WriteLine($"Using salt: {salt}");
            }

            // Brute-forcing easy passwords
            Console.WriteLine("\nBrute-forcing easy passwords:");
            foreach (var password in easyPasswords)
            {
                string passwordHash = HashPassword(password, hashAlgorithm, salt);
                Console.WriteLine($"\nTarget password (hashed): {passwordHash}");

                var result = RunBruteForceAttack(passwordHash, password.Length, hashAlgorithm, useMultithreading, charSet, salt);

                if (result.attempts > 0 && result.crackedPassword != null)
                {
                    Console.WriteLine($"Password '{result.crackedPassword}' cracked in {result.attempts:N0} attempts and {result.timeTaken:F2} seconds.");
                    results.Add(("Easy", password, result.attempts, result.timeTaken));
                }
                else
                {
                    Console.WriteLine($"Password '{password}' not cracked.");
                }
            }

            // Brute-forcing medium passwords
            Console.WriteLine("\nBrute-forcing medium passwords:");
            foreach (var password in mediumPasswords)
            {
                string passwordHash = HashPassword(password, hashAlgorithm, salt);
                Console.WriteLine($"\nTarget password (hashed): {passwordHash}");

                var result = RunBruteForceAttack(passwordHash, password.Length, hashAlgorithm, useMultithreading, charSet, salt);

                if (result.attempts > 0 && result.crackedPassword != null)
                {
                    Console.WriteLine($"Password '{result.crackedPassword}' cracked in {result.attempts:N0} attempts and {result.timeTaken:F2} seconds.");
                    results.Add(("Medium", password, result.attempts, result.timeTaken));
                }
                else
                {
                    Console.WriteLine($"Password '{password}' not cracked.");
                }
            }

            // Brute-forcing difficult passwords
            Console.WriteLine("\nBrute-forcing difficult passwords:");
            foreach (var password in difficultPasswords)
            {
                string passwordHash = HashPassword(password, hashAlgorithm, salt);
                Console.WriteLine($"\nTarget password (hashed): {passwordHash}");

                var result = RunBruteForceAttack(passwordHash, password.Length, hashAlgorithm, useMultithreading, charSet, salt);

                if (result.attempts > 0 && result.crackedPassword != null)
                {
                    Console.WriteLine($"Password '{result.crackedPassword}' cracked in {result.attempts:N0} attempts and {result.timeTaken:F2} seconds.");
                    results.Add(("Difficult", password, result.attempts, result.timeTaken));
                }
                else
                {
                    Console.WriteLine($"Password '{password}' not cracked.");
                }
            }

            // Analysis of results
            Console.WriteLine("\n--- Analysis of Results ---");
            var groupedResults = results.GroupBy(r => r.difficulty);

            foreach (var group in groupedResults)
            {
                Console.WriteLine($"\n{group.Key} Passwords:");
                double avgAttempts = group.Average(r => r.attempts);
                double avgTime = group.Average(r => r.timeTaken);
                Console.WriteLine($"Average Attempts: {avgAttempts:N0}");
                Console.WriteLine($"Average Time Taken: {avgTime:F2} seconds");

                foreach (var res in group)
                {
                    Console.WriteLine($"Password: {res.password}, Attempts: {res.attempts:N0}, Time: {res.timeTaken:F2} sec");
                }
            }
        }

        // Function to generate a random salt
        public static string GenerateRandomSalt(int size = 16)
        {
            byte[] saltBytes = new byte[size];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }
            return Convert.ToBase64String(saltBytes);
        }
    }
}
