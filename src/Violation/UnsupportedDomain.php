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

namespace Rollerworks\Component\X509Validator\Violation;

use Rollerworks\Component\X509Validator\Violation;

final class UnsupportedDomain extends Violation
{
    private readonly string $requiredPattern;
    /** @var array<array-key, string> */
    private readonly array $supported;

    public function __construct(string $requiredPattern, string ...$supported)
    {
        parent::__construct(sprintf("The provided domain-names are not supported by required pattern. Required: '%s'\nProvided: '%s'.", $requiredPattern, implode("', '", $supported)));

        $this->requiredPattern = $requiredPattern;
        $this->supported = $supported;
    }

    public function getTranslatorMsg(): string
    {
        return 'The certificate should support host pattern "{required_pattern}". But only the following patterns are supported: {supported}.';
    }

    public function getParameters(): array
    {
        return [
            'required_pattern' => $this->requiredPattern,
            'supported' => implode(', ', $this->supported),
        ];
    }
}
