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

final class MissingCAExtension extends Violation
{
    public function __construct(private readonly string $name)
    {
        parent::__construct('Certificate does not contain required "CA:true" in "extensions.basicExtension".');
    }

    public function getTranslatorMsg(): string
    {
        return 'Certificate with common-name "{common_name}" does not contain required CA extension.';
    }

    public function getParameters(): array
    {
        return ['common_name' => $this->name];
    }
}
