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

use Rollerworks\Component\X509Validator\Violation\MissingCAExtension;
use Rollerworks\Component\X509Validator\Violation\TooManyCAsProvided;
use Rollerworks\Component\X509Validator\Violation\UnableToResolveParent;

class CAResolverImpl implements CAResolver
{
    private readonly X509DataExtractor $extractor;

    public function __construct()
    {
        $this->extractor = new X509DataExtractor();
    }

    /**
     * @param array<string, string> $caList [identifiable-name => PEM-encoded-CA]
     *
     * @return CA|null returns null when certificate is self-signed (regardless of provided caList)
     */
    public function resolve(string $certificate, array $caList): ?CA
    {
        // Safety check to prevent DoS attacks
        // Normally only two parents are used, more than three is exceptional
        if (\count($caList) > 4) {
            throw new TooManyCAsProvided();
        }

        $certData = $this->extractor->extractRawData($certificate, '', true);

        if ($this->isSignatureValid($certificate, $certData->pubKey)) {
            return null;
        }

        return $this->resolveCA($certificate, $caList);
    }

    private function isSignatureValid(string $contents, string $pupKey): bool
    {
        $result = openssl_x509_verify($contents, $pupKey);

        if ($result === 1) {
            return true;
        }

        @openssl_error_string();

        return false;
    }

    /** @param array<string, string> $caList */
    private function resolveCA(string $certificate, array $caList): CA
    {
        foreach ($caList as $index => $contents) {
            $data = $this->extractor->extractRawData($contents, $index, true);
            $this->validateCA($data);

            if (! $this->isSignatureValid($certificate, $data->pubKey)) {
                continue;
            }

            // Check if self signed, otherwise resolve it's parent
            if (! $this->isSignatureValid($contents, $data->pubKey)) {
                // THIS issuer cannot be the parent of another parent, so remove it
                // from the list. This speeds-up the resolving process.
                unset($caList[$index]);

                $this->resolveCA($contents, $caList);
            }

            return new CA($contents);
        }

        $x509Info = $this->extractor->extractRawData($certificate);

        throw new UnableToResolveParent($x509Info->commonName, $x509Info->allFields['issuer']['commonName']);
    }

    private function validateCA(X509Info $data): void
    {
        if (! isset($data->allFields['extensions']['basicConstraints'])
            || mb_stripos((string) $data->allFields['extensions']['basicConstraints'], 'CA:TRUE') === false
        ) {
            throw new MissingCAExtension($data->allFields['subject']['commonName']);
        }
    }
}
