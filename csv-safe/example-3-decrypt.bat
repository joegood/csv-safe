
csv-safe.exe easy-test-2-safe.csv -d PASSWORD

:: csv-safe.exe [csv file to decrypt] [-d] or [--decrypt] (original password)
:: creates a new file with "-decrypted" added to the name.

:: There will be a new column added to the output, ROWCHECK.
:: This will contain "PASS" or "FAIL" indicating that all of the original encrypted fields were found to be the same as they were when the file was built.


pause