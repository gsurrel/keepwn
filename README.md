# KeePwn

Checks a [KeePass](https://keepass.info/) ([Wikipedia](https://en.wikipedia.org/wiki/KeePass)) database against the [Have I Been Pwned](https://haveibeenpwned.com/) service.

*Note: this tool performs network requests, but send only a fraction of the password hash, thus protecting your password.*

# Overview

1. KeePwn opens the database (as read-only),
2. iterate over all entries,
3. retrieve the password,
4. hashes it,
5. get the first chars of the hash to query the HIBP password API,
6. check whether the remaining of the password hash is present in the API's response,
7. prints to the terminal the result,

# Usage

```console
$ keepwn --help
KeePwn 0.1
Grégoire Surrel
Checks a KeePass database against the Have I Been Pwned service (https://haveibeenpwned.com/)

Note: this tool performs network requests, but send only a fraction of the password hash,
      thus protecting your password.

USAGE:
    keepwn [FLAGS] <INPUT>

FLAGS:
    -e, --email       List all the emails from the database
    -h, --help        Prints help information
    -p, --password    Check whether your passwords has been leaked
    -V, --version     Prints version information

ARGS:
    <INPUT>    Sets the KeePass file to use
```

# Example

```console
$ ./keepwn test_db.kdbx -e -p
Password to unlock test_db.kdbx: 
Entry 'Some title' (user 'totally_not_in_any_hibp_database_leak@nohost.tld'): password not breached ✅
Entry '' (user 'admin@example.com'): password breached ⚠️
Entry 'Entry without email but username' (user 'MyNickname'): password breached ⚠️

List of unique emails for manual check:
admin@example.com
totally_not_in_any_hibp_database_leak@nohost.tld
```

# It is slow!

Yes, because there is a [rate-limiting from the API, enforcing a 1.5s delay between requests](https://haveibeenpwned.com/API/v3#RateLimiting).

# Development

The test database `test_db.kdbx` is locked with the `password` password, and contains three entries:

- Root node, renamed as MyRoot
    - Entry:
        - No title
        - Username: *admin@example.com*
        - Password: *password*
        - URL: *http://example.com*
    - Entry:
        - Title: *Entry without email but username*
        - Username: *MyNickname*
        - Password: *MyPassword*
        - No URL
    - Sub-group
        - Entry:
            - Title: *Some title*
            - Username: *totally_not_in_any_hibp_database_leak@nohost.tld*
            - Password: *'=gT´L÷jsvª¥>É§àí%#qúZ®[.Ð·=í>Èß:që}f;Æ🔐;Çµá%cs{®º$øÙf7FÆ>ªñ%ÚÔÀªE-cÁUFê"P¬ÌP¾NêN¹q.C¢÷ÍA¥XæêÏ®ïâ*
            - URL: *nohost.tld*

# Choice of crates

This is a sensitive project, handling critical user data. Therefore, the choice of crates must be careful:

- [keepass](https://crates.io/crates/keepass) has a history of [tracking and addressing security vulnerabilities](https://github.com/sseemayer/keepass-rs/issues?q=is%3Aissue+is%3Aclosed)
- [checkpwn](https://crates.io/crates/checkpwn) gives me the impression to be sensible and not to do more than advertised
    - **Warning:** This is currently a binary crate rather than a library: the useful code has been copy-pasted in here
- [rpassword](https://crates.io/crates/rpassword) is a widely-used crate for password input
- [fast_chemail](https://crates.io/crates/fast_chemail) is the first result I found for checking email
