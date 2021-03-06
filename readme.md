# ida_yara
A python script that can be used to scan data within in an IDB using Yara. The code mimics [IDA](https://www.hex-rays.com/products/ida/support/idadoc/284.shtml)'s `find_text` and `find_binary`. The script creates the Yara signature based off of the search and its search flags.

## Requirements
 - Yara 3+

## Install
 - `git clone https://github.com/alexander-hanel/ida_yara.git`
 - `cd ida_yara`
 - `python-x64/python setup.py install`


## Usage
Same as IDA's `find_text` and `find_binary`.

`import ida_yara`

`ida_yara.yara_find_text(start_ea, y, x, ustr, sflag=0)`
 - `start_ea` = offset to start from
 - `x` = set to 0 (ignored)
 - `y` = set to 0 (ignored)
 - `ustr` = string pattern to search for. If regex, the `SEARCH_REGEX` must be passed as a sflag
 - `sflag` = if blank, search, ascii, down and return all matches

`ida_yara.yara_find_binary(start_ea, ubinstr, radix=16, sflag=0)`
 - `start_ea` = offset to start from
 - `ubinstr` = binary search pattern
 - `radix` = set to 0 (ignored)
 - `sflag` = if blank, search, down and return all matches

 Search Flags
 - `SEARCH_UP` = search up return single match
 - `SEARCH_DOWN` = search down return single match
 - `SEARCH_UP|SEARCH_NEXT` = return all up from ea with the order being closest to furthest
 - `SEARCH_DOWN|SEARCH_DOWN` = return all down from ea
 - `SEARCH_DOWN` = same as SEARCH_DOWN
 - `SEARCH_UNICODE` = search Unicode aka wide in Yara.
 - `SEARCH_CASE` = match case (not on by default)
 - `SEARCH_BRK` = ignored
 - `SEARCH_IDENT` = ignored
 - `SEARCH_NOSHOW` = ignored
 - `SEARCH_NOBRK` = ignored

## Example

### Binary Examples

Find all binary matches.
```
Python>ida_yara.yara_find_binary(here(), "56 8B",0)
[4199292L, 4199342L, 4200022L, 4203118L, 4203222L, 4204330L, 4204440L, 4204738L, 4205547L, 4205635L, 4205875L, 4206910L, 4207410L, 4207546L, 4208954L, 4209628L, 4209727L, 4212087L, 4212106L, 4212213L, 4212894L, 4212941L, 4213550L, 4213625L, 4213666L, 4213764L, 4213863L, 4215527L, 4215775L, 4215889L, 4215964L, 4216043L, 4216878L, 4216942L, 4217056L, 4217606L, 4218252L, 4218508L, 4222795L, 4222931L]
```
Find single match above single offset.
```
Python>ida_yara.yara_find_binary(here(), "56 8B",0, SEARCH_UP)
4212894
```
Find all matches above offset. Order is closest to furthest.
```
Python>ida_yara.yara_find_binary(here(), "56 8B",0, SEARCH_UP|SEARCH_NEXT)
[4212213L, 4212106L, 4212087L, 4209727L, 4209628L, 4208954L, 4207546L, 4207410L, 4206910L, 4205875L, 4205635L, 4205547L, 4204738L, 4204440L, 4204330L, 4203222L, 4203118L, 4200022L, 4199342L, 4199292L]
```
Find single match below offset.
```
Python>ida_yara.yara_find_binary(here(), "56 8B",0, SEARCH_DOWN)
4212894
```
Find all matches below offset.
```
Python>ida_yara.yara_find_binary(here(), "56 8B",0, SEARCH_DOWN|SEARCH_NEXT)
[4212894L, 4212941L, 4213550L, 4213625L, 4213666L, 4213764L, 4213863L, 4215527L, 4215775L, 4215889L, 4215964L, 4216043L, 4216878L, 4216942L, 4217056L, 4217606L, 4218252L, 4218508L, 4222795L, 4222931L]
```
### Text Examples
Find all ASCII text matches.
```
Python>ida_yara.yara_find_text(here(), 0,0, "Error")
[4228680L, 4228693L, 4228704L, 4231797L]
```
The same SEARCH_* flags can be used for text and regex also.
```
Python>ida_yara.yara_find_text(here(), 0,0, "Error", SEARCH_UP)
4228680
```
Find all UNICODE text matches.
```
Python>ida_yara.yara_find_text(here(), 0,0, "Error", SEARCH_UNICODE)
[4229044L]
```
### Regex Example

Find all text that match a regex.
```
Python>ida_yara.yara_find_text(here(), 0,0, "Err..", SEARCH_NEXT|SEARCH_DOWN|SEARCH_REGEX )
[4228680L, 4228693L, 4228704L, 4231611L, 4231797L]
```
## Notes
 - Very little error handling
 - IDA's search is not case-sensitive by default. This code is also not case-sensitive by default.   
 - I tried to match IDA arguments so some args do nothing but still need to be populated.
 - Much faster than IDA's search because the data is not constantly loaded.
 - If you edit the IDB, execute `reload_yara_mem` to resync the memory.


## Acknowledgments
 - Thanks to [Daniel Plohmann](https://twitter.com/push_pnx?lang=en) for writing code that allowed me not to
think about converting Yara match offsets to IDA virtual addresses.
 - Thanks to [HexRays](https://www.hex-rays.com/) for the support!
