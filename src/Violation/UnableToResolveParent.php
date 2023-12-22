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

final class UnableToResolveParent extends Violation
{
    public function __construct(private readonly string $name, private readonly string $issuer, int $code = 1)
    {
        parent::__construct(sprintf('Unable to resolve the parent CA of certificate "%s", issued by "%s".', $name, $issuer), $code);
    }

    public function getTranslatorMsg(): string
    {
        return 'Unable to resolve the CA of certificate "{name}", issued by {parent}.';
    }

    public function getParameters(): array
    {
        return ['name' => $this->name, 'parent' => $this->issuer];
    }
}
