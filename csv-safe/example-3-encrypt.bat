
csv-safe.exe easy-test-2.csv -e PASSWORD -c Name,Birthday,Gender,SSN 

:: csv-safe.exe [csv file to encrypt] [-e] or [--encrypt] (any password) -c Columns,To,Include,Cant,Have,Spaces
:: creates a new file with "-safe" added to the name.

:: This file is just a slightly different format than easy-test-1.
:: I also told it to encrypt the name, which has embeded quotes and multiple lines inserted.
pause