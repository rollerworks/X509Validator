<?php

declare(strict_types=1);

/*
 * This file is part of the Rollerworks X509Validator package.
 *
 * (c) Sebastiaan Stok <s.stok@rollerscapes.net>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Rollerworks\Component\X509Validator;

use ParagonIE\HiddenString\HiddenString;
use Rollerworks\Component\X509Validator\Violation\CertificateMismatch;
use Rollerworks\Component\X509Validator\Violation\KeyBitsTooLow;
use Rollerworks\Component\X509Validator\Violation\PublicKeyMismatch;
use Rollerworks\Component\X509Validator\Violation\UnprocessableKey;
use Rollerworks\Component\X509Validator\Violation\UnprocessablePEM;

class KeyValidator
{
    final public const MINIMUM_BIT_COUNT = 2048;

    /**
     * Validates if the provided private and certificate pair match.
     *
     * Internally this check if the public-key of the private-key
     * matches with the public key of the certificate. And Then performs
     * an additional check to ensure the key was not tempered with.
     *
     * @param HiddenString|string $privateKey  Private-key as PEM X509. Use HiddenString to prevent leaking
     *                                         sensitive information
     * @param string              $certificate Certificate as PEM X509 format string
     *
     * @throws UnprocessablePEM    when the data cannot be parsed or processed
     * @throws PublicKeyMismatch   when the public-keys don't match
     * @throws CertificateMismatch when the private doesn't match the certificate
     * @throws KeyBitsTooLow       when the private bits count is less than $minimumBitCount
     */
    public function validate(HiddenString | string $privateKey, string $certificate, int $minimumBitCount = self::MINIMUM_BIT_COUNT): void
    {
        $certR = @openssl_x509_read($certificate);

        if ($certR === false) {
            throw new UnprocessablePEM('');
        }

        $pupKey = openssl_pkey_get_public($certR);

        if (! $pupKey) {
            throw new UnprocessableKey('Unable to encrypt data, invalid key provided?');
        }

        $key = $privateKey instanceof HiddenString ? $privateKey->getString() : $privateKey;

        try {
            $privateR = @openssl_pkey_get_private($key);

            if ($privateR === false) {
                throw new UnprocessableKey('Unable to read private key-data, invalid key provided?');
            }

            if (! @openssl_x509_check_private_key($certR, $privateR)) {
                throw new PublicKeyMismatch();
            }

            // Note: technically it's rather difficult to replace the public-key
            // in a private-key (if not impossible?) yet openssl_x509_check_private_key() does
            // not provide full protection, so we use this additional check to prevent spoofing.

            // @codeCoverageIgnoreStart

            $original = "I just wanna tell you how I'm feeling\nGotta make you understand";
            $encrypted = '';

            if (! @openssl_public_encrypt($original, $encrypted, $pupKey, \OPENSSL_PKCS1_OAEP_PADDING)) {
                throw new UnprocessableKey('Unable to encrypt data, invalid key provided?');
            }

            if (! @openssl_private_decrypt($encrypted, $decrypted, $privateR, \OPENSSL_PKCS1_OAEP_PADDING) || $decrypted !== $original) {
                throw new CertificateMismatch();
            }

            $details = @openssl_pkey_get_details($privateR);

            if ($details === false) {
                throw new UnprocessableKey('Unable to read private key-data.');
            }
            // @codeCoverageIgnoreEnd

            if ($details['bits'] < $minimumBitCount) {
                throw new KeyBitsTooLow($minimumBitCount, $details['bits']);
            }
        } finally {
            if ($privateKey instanceof HiddenString) {
                sodium_memzero($key);
            }

            unset($key, $privateR, $pupKey, $certR);
        }
    }
}
