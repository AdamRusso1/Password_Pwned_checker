# Password_Pwned_checker
Project Title: Pwned Password Checker

Project Description:
The Pwned Password Checker is a command-line application designed to help users assess the security of their passwords by checking them against a database of compromised credentials. By leveraging the Pwned Passwords API and employing a secure k-anonymity model, the tool ensures that only a partial hash of each password is transmitted, maintaining user privacy while effectively determining if a password has been exposed in any known data breaches.

Users can either input passwords directly in a space-separated format or provide a text file containing a list of passwords. The application computes the SHA-1 hash for each password and sends the first five characters of the hash to the API. It then processes the response to determine the number of times the remainder of the hash appears in breached data, alerting users to potential vulnerabilities.

Key Features and Technologies:

Python 3: The core programming language used to build the application.
Requests Library: Facilitates secure HTTP requests to the Pwned Passwords API.
Hashlib Module: Used to generate SHA-1 hashes of user passwords.
Command-Line Interface: Provides a user-friendly way to input passwords and receive real-time feedback.
Secure API Integration: Implements the k-anonymity model to ensure user passwords are checked without compromising their security.
This project not only emphasizes best practices in secure API usage and error handling but also demonstrates practical application of cryptographic hashing in real-world security scenarios.
