
# Binary Sanitizing and Security Checker

A command-line tool that analyzes binary files to detect enabled security and sanitizing features.

## Repository

The project is hosted on GitHub: [Binary Security Checker](https://github.com/FHNW-Security-Lab/Sanitizing-Checker)

Clone the repository using:

```bash
git clone https://github.com/FHNW-Security-Lab/Sanitizing-Checker.git
```

## Usage

To run the Binary Security Checker, use the following command:

```bash
python3 sanitizing-checker.py <binary>
```

## Testing with Sample Binaries

The `test` folder contains sample binaries to try out the tool. Navigate to the `test` folder and run `main` to experiment with these samples.
```bash
cd test
make
cd ..
```


## Example Output

Running the tool on a binary will produce output similar to this:

```
$ python3 sanitizing-checker.py test/security_all_on

Security Features Analysis for: test/security_all_on
----------------------------------------
ASLR:                  Enabled
NX/DEP:                Enabled
PIE:                   Enabled
RELRO:                 Enabled
Stack Protection:      Enabled

Sanitizer Features:
----------------------------------------
AddressSanitizer:     Disabled
ThreadSanitizer:      Disabled
MemorySanitizer:      Disabled
UBSan:                Disabled

Coverage Features:
----------------------------------------
Function:             Disabled
Basic Block:          Disabled
Edge:                 Disabled
Trace:                Disabled  (None)
```

**Note:** Only the trace coverage feature is currently tested.

## License

This project is licensed under BSD 3-Clause Licence.




