# timmit/xss-filter

Checks and cleans strings with [voku/anti-xss](https://github.com/voku/anti-xss). The class is `TiMMiT\XSS_Filter`.

## Install

```bash
composer require timmit/xss-filter
```

This package requires `voku/anti-xss` ^4.1. Composer loads the class from `src/TiMMiT/XSS-Filter/XSS_Filter.php`.

## Usage

`check4XSSInRequestArrays()` scans `$_POST`, `$_GET`, and `$_COOKIE`. It returns `true` when XSS is found.

```php
use TiMMiT\XSS_Filter;

if (XSS_Filter::check4XSSInRequestArrays(true)) {
    // a value in $_POST, $_GET, or $_COOKIE contained XSS
}
```

The first argument writes cleaned strings back into those arrays when it is `true`. The second argument chooses the tag list: `true` blocks the known HTML tags, `false` blocks `img`, `a`, `b`, `strong`, and `i`. `null` keeps the list from the previous call. The default is the shorter list. The third argument also scans string keys.

`detectXSSInArray()` does the same walk for one array, including nested arrays:

```php
$found = XSS_Filter::detectXSSInArray($payload, true, true, true);
```

`cleanString()` returns the cleaned string and does not report whether XSS was found:

```php
$clean = XSS_Filter::cleanString($value, true);
```

`reset()` drops the current cleaner, so the next call builds a new one.

## License

MIT.
