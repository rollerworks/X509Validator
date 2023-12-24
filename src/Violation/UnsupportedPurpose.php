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

use Rollerworks\Component\X509Validator\TranslatableArgument;
use Rollerworks\Component\X509Validator\Violation;

final class UnsupportedPurpose extends Violation
{
    private readonly string $requiredPurpose;

    public function __construct(string $requiredPurpose)
    {
        parent::__construct(sprintf('Certificate does not support purpose: %s.', $requiredPurpose));

        $this->requiredPurpose = $requiredPurpose;
    }

    public function getTranslatorMsg(): string
    {
        return 'The certificate does not support the purpose: {required_purpose}.';
    }

    public function getParameters(): array
    {
        return [
            'required_purpose' => new TranslatableArgument($this->requiredPurpose, domain: 'messages'),
        ];
    }
}
