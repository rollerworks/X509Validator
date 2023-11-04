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

final class KeyBitsTooLow extends Violation
{
    private readonly int $expected;
    private readonly int $provided;

    public function __construct(int $expected, int $provided)
    {
        parent::__construct(sprintf('Private-key bits size %d lower than required %d.', $provided, $expected));

        $this->expected = $expected;
        $this->provided = $provided;
    }

    public function getTranslatorMsg(): string
    {
        return 'The private-key bits-size {provided} is too low. Expected at least {expected} bits.';
    }

    public function getParameters(): array
    {
        return [
            'expected' => $this->expected,
            'provided' => $this->provided,
        ];
    }
}
