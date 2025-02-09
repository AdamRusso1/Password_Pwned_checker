import requests
import hashlib


def main():
    while True:
        # Get user input - either a file path or space-separated passwords
        user_input = input(
            'Please enter either the path of the text file containing your passwords (more secure) or enter the '
            'passwords you would like to check in a space seperated format: ').strip()
        # Validate input is not empty
        if not user_input:
            print('Please enter a valid input')
            continue

        try:
            # Attempt to open input as a file first
            with open(user_input, 'r') as f:
                # If file opens successfully, process passwords from file
                from_file(user_input)
                break
        except (FileNotFoundError, OSError):
            # Check if input resembles a file path using predefined indicators
            if looks_like_file_path(user_input):
                # If it looks like a file path, confirm user's intention
                confirmation = input('Did you intend to supply a file path? (y/n): ').strip().lower()
                if confirmation == 'y':
                    print('File does not exist! please check path and try again')
                    continue

            # Process input as space-separated list of passwords
            password_list = [item for item in user_input.split() if item]
            from_list(password_list)
            break


def looks_like_file_path(input_string):
    """
        Common file path indicators for checking user input
        Returns True if input matches any common file path patterns
    """
    indicators = [
        '/' in input_string,  # Unix-style paths
        '\\' in input_string,  # Windows-style paths
        '.txt' in input_string.lower(),  # Common text file extension
        '.' in input_string and len(input_string.split()) == 1,  # Has extension and is single word
        ':' in input_string,  # Drive letters (Windows)
        input_string.startswith('~/')  # Home directory
    ]
    return any(indicators)


def from_file(filename):
    """
       Reads passwords from the file and checks each against the Pwned Passwords API.
       Returns True if the file was processed successfully, False otherwise.
       Skips empty lines in the file.
    """
    try:
        with open(filename, 'r') as file:
            for password in file:
                password = password.strip()
                if password:  # skips empty lines
                    count = pwned_api_check(password)
                    print(f"Password: {password} was found {count} times")
        return True

    except Exception as e:
        print(f"An error has occurred while reading this file : {e}")
        return False


def from_list(list_input):
    """
        Checks each password in the list against the Pwned Passwords API.
        Prints whether each password was found in data breaches and how many times.
        Returns 'done!' when processing is complete.
    """
    for password in list_input:
        count = pwned_api_check(password)
        if count:
            print(f"Password: {password} was found {count} times")
        else:
            print(f"Password: {password} was NOT found")
    return 'done!'


def request_api_data(query_char):
    """
        Queries the Pwned Passwords API with the given prefix (first 5 characters of the hash).
        Uses k-anonymity model: only first 5 chars of hash are sent to API.
        Raises RuntimeError if API request fails.
    """
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    try:
        res = requests.get(url)
        res.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f"Error fetching: {e}, check the API and try again")
    return res


def get_password_leaks_count(hashes, hash_to_check):
    """
        Parses the API response and returns the number of times the password hash (tail) was found.
        Returns 0 if the hash wasn't found in the leaked passwords database.
        hashes: API response containing hash suffixes and their counts
        hash_to_check: remainder of the hash (after first 5 chars) to look for
    """
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return int(count)
    return 0


def pwned_api_check(password):
    """
        Computes the SHA-1 hash of the password, queries the API, and returns the leak count.
        Process:
        1. Convert password to SHA-1 hash
        2. Split hash into first 5 chars and remainder
        3. Query API with first 5 chars
        4. Check if remainder exists in response
    """
    # check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)  # here hash_to_check is tail and hashes = response


if __name__ == '__main__':
    main()
