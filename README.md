Password Cracker Simulation
This project is a Password Cracker Simulation written in C#. It demonstrates various password hashing algorithms and simulates a brute-force attack on passwords using different configurations, including multi-threading and salting.

Features:

Supports multiple hashing algorithms:
MD5
SHA-256
BCrypt
Argon2

Option to enable or disable salting.
Supports multi-threading for faster brute-force attacks.

Allows users to choose from various character sets for brute-force attacks:
Numeric (0-9)
Lowercase letters (a-z)
Uppercase letters (A-Z)
Alphanumeric (0-9, a-z, A-Z)
All printable ASCII characters
Allows users to input their own custom passwords or run predefined brute-force simulations.
Detailed analysis of brute-force attempts, including average time and attempts for different difficulty levels (easy, medium, difficult passwords).

Setup
Clone this repository:
git clone https://github.com/Amir-Azag/Brute-Force-Attack-Simulator.git
Open the solution in Visual Studio.

Build the solution and ensure all dependencies are installed.

Run the program and follow the prompts in the console.

Usage
Custom Password Mode
You can choose to input your own password, specify the maximum password length to be attempted, and select the hashing algorithm. The program will hash your password and attempt to brute-force it.

Predefined Simulation Mode
If you choose not to enter a custom password, the program will run predefined simulations on easy, medium, and difficult passwords. The results of these brute-force attacks will be displayed, including the number of attempts and the time taken.

Example of Options:
Choose hashing algorithm: md5, sha256, bcrypt, or argon2
Enable salting (yes/no)
Enable multi-threading (yes/no)
Choose character set:
Numeric
Lowercase
Uppercase
Alphanumeric
All printable ASCII characters

Dependencies
BCrypt.Net: For bcrypt hashing.
Isopoh.Cryptography.Argon2: For argon2 hashing.
Standard libraries for MD5 and SHA-256.

Example Output
Here’s an example of the program’s output after cracking a password:
Password '1234' cracked in 10,000 attempts and 0.02 seconds.
Average Attempts: 50,000
Average Time Taken: 0.10 seconds

