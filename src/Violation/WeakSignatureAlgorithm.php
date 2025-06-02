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

final class WeakSignatureAlgorithm extends Violation
{
    private readonly string $expected;
    private readonly string $provided;

    public function __construct(string $expected, string $provided)
    {
        parent::__construct(\sprintf('Certificate signature is too weak, expected at least "%s" but got "%s"', $expected, $provided));

        $this->expected = $expected;
        $this->provided = $provided;
    }

    public function getTranslatorMsg(): string
    {
        return 'The certificate was signed using the weak "{provided}" algorithm. Expected at least algorithm "{expected}".".';
    }

    public function getParameters(): array
    {
        return [
            'expected' => $this->expected,
            'provided' => $this->provided,
        ];
    }
}
