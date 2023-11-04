Rollerworks X509Validator
=========================

This package provides X509 TLS certificate/private-key validators to
validate the following:

* CA chain completeness
* PrivateKey bits length
* Signature algorithm
* OCSP Revocation status (requires internet access)
* Certificate purpose
* Certificate general validity (private-key compatibility, not expired, readable)
* Certificate hostname pattern supported, and protection
  against global wildcards of public-suffix length violations

**Tip:** Violations can be easily translated using the Symfony Translator
component and provided translations.

Use the [X509Validator Symfony Constraints][x509-sf] (separate package)
to these validators with the Symfony Validator component.

## Installation

To install this package, add `rollerworks/x509-validator` to your composer.json:

```bash
$ php composer.phar require rollerworks/x509-validator
```

Now, [Composer][composer] will automatically download all required files,
and install them for you.

## Requirements

You need at least PHP 8.1, internet access is required if you want to
validate a certificate's OCSP status.

## Basic Usage

The `CertificateValidator` and `KeyValidator` are to primary validators
for validating a certificate or private-key encoded in PEM (base64), 
DER (binary) is not supported.

See (documentation)[docs/index.md] for usage of all validators.

## Versioning

For transparency and insight into the release cycle, and for striving to
maintain backward compatibility, this package is maintained under the
Semantic Versioning guidelines as much as possible.

Releases will be numbered with the following format:

`<major>.<minor>.<patch>`

And constructed with the following guidelines:

* Breaking backward compatibility bumps the major (and resets the minor and patch)
* New additions without breaking backward compatibility bumps the minor (and resets the patch)
* Bug fixes and misc changes bumps the patch

For more information on SemVer, please visit <http://semver.org/>.

## License

This library is released under the [MIT license](LICENSE).

## Contributing

This is an open source project. If you'd like to contribute,
please read the [Contributing Guidelines][contributing]. If you're submitting
a pull request, please follow the guidelines in the [Submitting a Patch][patches] section.

[composer]: https://getcomposer.org/doc/00-intro.md
[flex]: https://symfony.com/doc/current/setup/flex.html
[contributing]: https://contributing.rollerscapes.net/
[patches]: https://contributing.rollerscapes.net/latest/patches.html
