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

final class X509Info
{
    /** @var array<int, string> */
    public readonly array $altDomains;
    /** @var array<int, string> */
    public readonly array $altNames;
    public readonly string $commonName;
    /** @var array<int, string> */
    public readonly array $domains;
    /** @var array<int, string> */
    public readonly array $emails;
    public readonly string $fingerprint;
    public readonly string $pubKey;
    public readonly string $signatureAlgorithm;
    public readonly \DateTimeImmutable $validFrom;
    public readonly \DateTimeImmutable $validTo;

    /**
     * Contains all fields, including 'raw' x509 data provided by `openssl_x509_read()`.
     *
     * Note: Extra fields begin with an underscore.
     *
     * @var array<string, mixed>
     */
    public readonly array $allFields;

    /** @param array<string, mixed> $fields */
    public function __construct(array $fields)
    {
        $this->altDomains = $fields['_alt_domains'] ?? [];
        $this->altNames = $fields['_altNames'] ?? [];
        $this->commonName = $fields['_commonName'] ?? '';
        $this->domains = $fields['_domains'] ?? [];
        $this->emails = $fields['_emails'] ?? [];
        $this->fingerprint = $fields['_fingerprint'] ?? '';
        $this->pubKey = $fields['_pubKey'] ?? '';
        $this->signatureAlgorithm = $fields['_signatureAlgorithm'] ?? '';
        $this->validFrom = $fields['_validFrom'] ?? new \DateTimeImmutable('-1 year');
        $this->validTo = $fields['_validTo'] ?? new \DateTimeImmutable('+1 year');

        $this->allFields = $fields;
    }
}
