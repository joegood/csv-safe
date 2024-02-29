
csv-safe.exe easy-test-1L.csv -o big-honking-encrypted-file.csv -e PASSWORD -c Birthday,Gender,SSN,Junk,Added,To,Show,What,Happens 

:: csv-safe.exe [csv file to encrypt] -o [output file] [-e] or [--encrypt] (any password) -c Columns,To,Include,Cant,Have,Spaces
:: creates the file specified with the -o option.

:: This demo also shows how it works on a 300,000 row file and bad columns put into the column list.

pause