csv-safe.exe big-honking-encrypted-file.csv -o original-big-honking-file.csv -d PASSWORD

:: csv-safe.exe [csv file to decrypt] [-d] or [--decrypt] (original password)
:: creates a file provided by the -o option.

:: There will be a new column added to the output, ROWCHECK.
:: This will contain "PASS" or "FAIL" indicating that all of the original encrypted fields were found to be the same as they were when the file was built.

pause
