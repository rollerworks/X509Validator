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

use Pdp\Domain;
use Pdp\PublicSuffixList;
use Psr\Clock\ClockInterface;
use Rollerworks\Component\X509Validator\Violation\CertificateHasExpired;
use Rollerworks\Component\X509Validator\Violation\GlobalWildcard;
use Rollerworks\Component\X509Validator\Violation\UnsupportedDomain;
use Rollerworks\Component\X509Validator\Violation\UnsupportedPurpose;
use Rollerworks\Component\X509Validator\Violation\WeakSignatureAlgorithm;

class CertificateValidator
{
    final public const PURPOSE_SMIME = 'S/MIME';
    final public const PURPOSE_SMIME_SIGNING = 'S/MIME signing';
    final public const PURPOSE_SMIME_ENCRYPTION = 'S/MIME encryption';

    final public const PURPOSE_SSL_CLIENT = 'SSL client';
    final public const PURPOSE_SSL_SERVER = 'SSL server';

    private readonly X509DataExtractor $extractor;
    private readonly CAResolver $caResolver;

    /**
     * @param X509DataExtractor|null $dataExtractor This should be reused by the validators
     *                                              to allow better caching
     * @param CAResolver|null        $caResolver    Use a custom CAResolver that stores CAs
     */
    public function __construct(
        private readonly PublicSuffixList $publicSuffixList,
        X509DataExtractor $dataExtractor = null,
        CAResolver $caResolver = null,
        private ?ClockInterface $clock = null
    ) {
        $this->extractor = $dataExtractor ?? new X509DataExtractor();
        $this->caResolver = $caResolver ?? new CAResolverImpl();
    }

    /**
     * @param array<string, string> $caList
     *
     * @throws Violation
     */
    public function validateCertificate(string $certificate, array $caList = [], bool $allowWeakAlgorithm = false): void
    {
        $data = $this->extractRawData($certificate);

        $this->validateNotExpired($data->validTo);
        $this->validateDomainsWildcard($data->domains);

        if (! $allowWeakAlgorithm) {
            $this->validateSignatureAlgorithm($data->allFields['signatureTypeLN']);
        }

        // Don't skip this stop when the CA list is empty, as CA's should still be valid.
        $this->caResolver->resolve($certificate, $caList);
    }

    protected function extractRawData(string $contents): X509Info
    {
        return $this->extractor->extractRawData($contents);
    }

    private function validateNotExpired(\DateTimeInterface $validTo): void
    {
        if ($validTo < $this->getNow()) {
            throw new CertificateHasExpired($validTo);
        }
    }

    private function validateSignatureAlgorithm(string $signatureType): void
    {
        $normSignatureType = mb_strtolower((string) preg_replace('/(WithRSAEncryption$)|(^ecdsa-with-)/i', '', $signatureType));

        // While sha224 is considered the same as sha256 it's no longer part of TLS 1.3
        if (\in_array($normSignatureType, ['none', 'md2', 'md5', 'sha1', 'sha224', ''], true)) {
            throw new WeakSignatureAlgorithm('SHA256', $signatureType);
        }
    }

    /** @param array<array-key, string> $domains */
    private function validateDomainsWildcard(array $domains): void
    {
        foreach ($domains as $domain) {
            if (! str_contains($domain, '*')) {
                continue;
            }

            if ($domain === '*') {
                throw new GlobalWildcard($domain, '*');
            }

            $domainInfo = $this->publicSuffixList->resolve(Domain::fromIDNA2008($domain));

            if (! $domainInfo->suffix()->isKnown()) {
                return;
            }

            $publicSuffix = $domainInfo->suffix()->toString();

            if (rtrim(mb_substr($domainInfo->toString(), 0, -mb_strlen($publicSuffix)), '.') === '*') {
                throw new GlobalWildcard($domain, $publicSuffix);
            }
        }
    }

    /** @param self::PURPOSE_* ...$requiredPurpose */
    public function validateCertificatePurpose(string $certificate, string ...$requiredPurpose): void
    {
        $requiredPurposes = array_fill_keys($requiredPurpose, true);

        if (isset($requiredPurposes[self::PURPOSE_SMIME])) {
            unset($requiredPurposes[self::PURPOSE_SMIME]);

            $requiredPurposes['S/MIME signing'] = true;
            $requiredPurposes['S/MIME encryption'] = true;
        }

        $purposes = [];

        foreach ($this->extractRawData($certificate)->allFields['purposes'] as $purpose) {
            $purposes[$purpose[2]] = $purpose[0];
        }

        foreach ($requiredPurposes as $requirement => $v) {
            if (($purposes[$requirement] ?? false) === false) {
                throw new UnsupportedPurpose($requirement);
            }
        }
    }

    public function validateCertificateHost(string $certificate, string $hostPattern): void
    {
        $this->validateCertificatePurpose($certificate, self::PURPOSE_SSL_SERVER);

        $data = $this->extractRawData($certificate);

        foreach ($data->domains as $value) {
            if (preg_match('#^' . str_replace(['.', '*'], ['\.', '[^.]*'], (string) $value) . '$#', $hostPattern)) {
                return;
            }
        }

        throw new UnsupportedDomain($hostPattern, ...$data->domains);
    }

    /**
     * Allows to use a custom callable validator which receives the Certificate
     * information for advanced validation.
     *
     * Should throw an custom exception on failure.
     *
     * @param callable(X509Info, string, $this): void $validator {X509Info object, certificate, $this}
     */
    public function validateCertificateSupport(string $certificate, callable $validator): void
    {
        $data = $this->extractRawData($certificate);
        $validator($data, $certificate, $this);
    }

    private function getNow(): \DateTimeImmutable
    {
        return $this->clock?->now() ?? new \DateTimeImmutable();
    }
}
