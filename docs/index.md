Basic Usage
===========

This library consists of multiple validators, the `CertificateValidator`
being the main one. All other validators assume this validator is always
used prior to advanced-level validation.

Composer autoloader is assumed for all examples.

All validators except the `KeyValidator` use the `X509DataExtractor`,
while this argument is not required for the validators it's recommended
to create one instance pass this the validator constructors, as the
extractor keeps a single-cache of the last used certificate.

Secondly a `CAResolver` instance is used, which can be replaced with
a custom implementation to either store a CA chain or trying to retrieve
from a global database. See [Custom CAResolver]([ca_resolver.md](ca_resolver.md))
for more information.

```php
use Rollerworks\Component\X509Validator\X509DataExtractor;

$dataExtractor = new X509DataExtractor();
```

In the case of a violation a specific exception which extends the
`Rollerworks\Component\X509Validator\Violation` class is thrown.

See [Working with validation Violations] below.

## Using the CertificateValidator

Note that `CertificateValidator` requires a `Rollerworks\Component\PdbSfBridge\PdpManager`
instance, see https://github.com/rollerworks/PdbSfBridge to set-up a new instance.

The `CertificateValidator` validates:

* CA chain completeness;
* Signature algorithm;
* Certificate is not expired;
* Certificate hostname pattern contains no global wildcards 
  or public-suffix length violations;

```php
use Rollerworks\Component\PdbSfBridge\PdpManager;
use Rollerworks\Component\X509Validator\CertificateValidator;

/** @var PdpManager $pdbManager */
$pdbManager = ...;

$validator = new CertificateValidator($pdbManager, /*$dataExtractor*/);

 // PEM X509 encoded certificate string
$certificate = '';

 // PEM X509 encoded CA string as value, key can be (file)name for reverence (order doesn't matter)
$caList = [];

// WARNING the allowWeakAlgorithm argument allows to disable Algorithm validation!
// By default only sha256 or higher is considered safe.
$validator->validateCertificate($certificate, $caList, /*allowWeakAlgorithm: false)*/);
```

### Validating required purpose

The `CertificateValidator` allows to validate if certificate can be used
for a specific purpose, like SSL-server, S/MIME encryption/signing.

**Note:** This should be called _after_ `validateCertificate()`.

```php
use Rollerworks\Component\X509Validator\CertificateValidator;

/** @var CertificateValidator $validator */
$validator = ...;

// Any of the CertificateValidator::PURPOSE_* constants.
// CertificateValidator::PURPOSE_SMIME includes both signing and encryption
$validator->validateCertificatePurpose($certificate, CertificateValidator::PURPOSE_SSL_SERVER);

// Multiple purpose names as variadic are allowed.
$validator->validateCertificatePurpose($certificate, CertificateValidator::PURPOSE_SSL_CLIENT, CertificateValidator::PURPOSE_SSL_SERVER));
```

Throws `Rollerworks\Component\X509Validator\Violation\UnsupportedPurpose`.

### Validating hosts compatibility

The `CertificateValidator` allows to validate if certificate hostname(s)
are supported by a specific name or pattern. Including alt-names.

**Note:** This should be called _after_ `validateCertificate()`.

```php
use Rollerworks\Component\X509Validator\CertificateValidator;

/** @var CertificateValidator $validator */
$validator = ...;

$validator->validateCertificateHost($certificate, 'example.com');

// Wildcard is supported
$validator->validateCertificateHost($certificate, '*.example.com');
```

Throws `Rollerworks\Component\X509Validator\Violation\UnsupportedDomain`
with a list of supported hostnames.

### Validating custom conditions

The `CertificateValidator` allows to validate if certificate can be used
with specific condition that are too custom for regular validator.

**Note:** This should be called _after_ `validateCertificate()`.

```php
use Rollerworks\Component\X509Validator\CertificateValidator;
use Rollerworks\Component\X509Validator\Violation;
use Rollerworks\Component\X509Validator\X509Info;

/** @var CertificateValidator $validator */
$validator = ...;

final class EmailFieldRequired extends Violation
{
    public function __construct()
    {
        parent::__construct('This certificate should contains an emails extension.');
    }

    public function getTranslatorMsg(): string
    {
        return 'This certificate should contains an emails extension.';
    }
}

// The $info argument contains all the raw information extracted from
// the certificate. Field starting with underscore are validator specific.
$customValidator = function (X509Info $info, string $certificate, CertificateValidator $validator ) {
    if (count($info->emails) === 0) {
        throw new EmailFieldRequired();
    }
};

$validator->validateCertificateSupport($certificate, $customValidator);
```

## Using the KeyValidator

The `KeyValidator` validates if the certificate is compatible with the provided
private-key, and if the private-key fulfills the minimum bit-length. 

```php
use Rollerworks\Component\X509Validator\KeyValidator;

$validator = new KeyValidator();

// PEM X509 encoded private-key string
$privateKey = '';

// OR a ParagonIE HiddenString object to prevent leaking information
// into core-dumps or system logs.
// $privateKey = new \ParagonIE\HiddenString\HiddenString('');

 // PEM X509 encoded certificate string
$certificate = '';

// minimumBitCount is 2048 but be increased or lowered at will
$validator->validate($privateKey, $certificate, /*minimumBitCount: KeyValidator::MINIMUM_BIT_COUNT*/);
```

**Throws:**

* `Rollerworks\Component\X509Validator\Violation\UnprocessablePEM`:    when the data cannot be parsed or processed
* `Rollerworks\Component\X509Validator\Violation\PublicKeyMismatch`:   when the public-keys don't match
* `Rollerworks\Component\X509Validator\Violation\CertificateMismatch`: when the private doesn't match the certificate
* `Rollerworks\Component\X509Validator\Violation\KeyBitsTooLow`:       when the private bits count is less than $minimumBitCount

## Using the OCSPValidator

The `OCSPValidator` validates the revocation status of a certificate,
for this to work internet access is required, and the certificate must
have a CA.

First make sure the ``

This validator should be called after general validation with the `CertificateValidator`.

All arguments are optional, if not provided will be created as shown 
in the example.

```php
use Rollerworks\Component\X509Validator\OCSPValidator;

$httpClient = \Symfony\Component\HttpClient\HttpClient::create();
$logger = new \Psr\Log\NullLogger(); // Replace an actual logger for server errors
$caResolver = new \Rollerworks\Component\X509Validator\CAResolverImpl();

$validator = new OCSPValidator($httpClient, $logger, $caResolver);

 // PEM X509 encoded certificate string
$certificate = '';

 // PEM X509 encoded CA string as value, key can be (file)name for reverence (order doesn't matter)
$caList = [];

$validator->validateStatus($certificate, $caList);
```

Throws `Rollerworks\Component\X509Validator\Violation\CertificateIsRevoked` with
reason of revocation, and date (if available).

## Working with validation Violations

All violations contain a technical message which can be safely displayed
publicly like an API REST response without the need for redacting.

To display a violation as user-friendly error message either use the 
`getTranslatorMsg()` and `getParameters()` methods to render a message.

Or call the `trans()` method with a `Symfony\Contracts\Translation\TranslatorInterface` 
translator.  Translations are provided in xliff.

**Note:** Make sure the translator instance support ICU formatting and translates
`TranslatableInterface` implementing parameters.
