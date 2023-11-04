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

final class GlobalWildcard extends Violation
{
    private readonly string $provided;
    private readonly string $suffixPattern;

    public function __construct(string $provided, string $suffixPattern)
    {
        parent::__construct(
            sprintf(
                'The certificate supported domain "%s" contains a global wildcard with suffix pattern "%s"',
                $provided,
                $suffixPattern
            )
        );

        $this->provided = $provided;
        $this->suffixPattern = $suffixPattern;
    }

    public function getTranslatorMsg(): string
    {
        if ($this->suffixPattern === '*') {
            return 'The certificate host "{provided}" contains an invalid global-wildcard pattern.';
        }

        return 'The certificate host "{provided}" contains an invalid public-suffix wildcard pattern "{suffix_pattern}".';
    }

    public function getParameters(): array
    {
        return [
            'provided' => $this->provided,
            'suffix_pattern' => $this->suffixPattern,
        ];
    }
}
