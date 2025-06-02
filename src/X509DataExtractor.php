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
use Rollerworks\Component\X509Validator\Violation\UnprocessablePEM;

final class X509DataExtractor
{
    private ?string $hash = null;
    private ?X509Info $fields = null;

    /** @throws UnprocessablePEM */
    public function extractRawData(string $contents, string $name = '', bool $withPublicKey = false): X509Info
    {
        $hash = hash('sha256', $contents);

        // The same cert information is likely to be validated multiple times
        // So keep a local cache to speed-up the parsing process a little.
        if ($hash === $this->hash && isset($this->fields)) {
            return $this->fields;
        }

        $x509Read = @openssl_x509_read($contents);

        if ($x509Read === false) {
            throw new UnprocessablePEM($name, $contents);
        }

        // @codeCoverageIgnoreStart
        $rawData = @openssl_x509_parse($x509Read, false);

        if ($rawData === false) {
            throw new UnprocessablePEM($name, $contents);
        }

        try {
            $fingerprint = @openssl_x509_fingerprint($x509Read, $rawData['signatureTypeSN']) ?: '';
        } catch (\Throwable) {
            $fingerprint = '';
        }

        if ($withPublicKey) {
            $pubKeyRead = openssl_pkey_get_public($x509Read);

            if ($pubKeyRead === false) {
                throw new UnprocessablePEM($name, $contents);
            }

            $pubKey = openssl_pkey_get_details($pubKeyRead) ?: [];

            unset($pubKeyRead, $x509Read);
        } else {
            $pubKey = [];
        }
        // @codeCoverageIgnoreEnd

        $altNames = $this->getAltNames($rawData);
        $rawData += [
            '_commonName' => mb_trim((string) $rawData['subject']['commonName']),
            '_altNames' => $altNames,
            '_emails' => $altNames['rfc822'] ?? [],
            '_signatureAlgorithm' => $rawData['signatureTypeSN'],
            '_fingerprint' => $fingerprint,
            '_validTo' => new \DateTimeImmutable('@' . $rawData['validTo_time_t']),
            '_validFrom' => new \DateTimeImmutable('@' . $rawData['validFrom_time_t']),
            '_pubKey' => $pubKey['key'] ?? '',
        ];

        $rawData['_domains'] = array_merge($rawData['_altNames']['dns'] ?? [], $rawData['_altNames']['ip address'] ?? []);
        $rawData['_alt_domains'] = $rawData['_domains'];
        $rawData['_domains'][] = $rawData['_commonName'];

        // Remove any duplicates and ensure the keys are incremental.
        $rawData['_domains'] = array_unique($rawData['_domains']);

        $this->hash = $hash;
        $this->fields = new X509Info($rawData);

        return $this->fields;
    }

    /**
     * @param array<string, mixed> $rawData
     *
     * @return array<string, array<int, string>>
     */
    private function getAltNames(array $rawData): array
    {
        if (! isset($rawData['extensions']['subjectAltName'])) {
            return [];
        }

        $altNames = [];

        foreach (explode(',', (string) $rawData['extensions']['subjectAltName']) as $altName) {
            [$type, $value] = explode(':', mb_trim($altName), 2);
            $altNames[mb_strtolower($type)][] = $value;
        }

        return $altNames;
    }

    /** @return array<string, mixed> */
    public function getPrivateKeyDetails(HiddenString | string $privateKey): array
    {
        $key = $privateKey instanceof HiddenString ? $privateKey->getString() : $privateKey;

        // @codeCoverageIgnoreStart
        try {
            $r = openssl_pkey_get_private($key);

            // Note that the KeyValidator will already check if the key is in-fact valid.
            // This failure will only happen in exceptional situations.
            if ($r === false) {
                throw new \RuntimeException('Unable to read private key-data, invalid key provided?');
            }

            $details = openssl_pkey_get_details($r);

            if ($details === false) {
                throw new \RuntimeException('Unable to read private key-data. Unknown error.');
            }
        } finally {
            unset($r);

            if ($privateKey instanceof HiddenString) {
                sodium_memzero($key);
            }
        }
        // @codeCoverageIgnoreEnd

        return [
            'bits' => $details['bits'],
            'type' => $details['type'],
        ];
    }
}
