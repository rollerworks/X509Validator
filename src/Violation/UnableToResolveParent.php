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
    private readonly string $name;

    public function __construct(string $name, int $code = 1)
    {
        parent::__construct(sprintf('Unable to resolve the parent CA of certificate "%s".', $name), $code);

        $this->name = $name;
    }

    public function getTranslatorMsg(): string
    {
        return 'Unable to resolve the CA of certificate "{name}".';
    }

    public function getParameters(): array
    {
        return ['name' => $this->name];
    }
}
