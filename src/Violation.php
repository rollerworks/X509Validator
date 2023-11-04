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

use Symfony\Contracts\Translation\TranslatableInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

abstract class Violation extends \InvalidArgumentException implements TranslatableInterface
{
    abstract public function getTranslatorMsg(): string;

    /** @return array<string, mixed> */
    public function getParameters(): array
    {
        return [];
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return [
            'message' => $this->getTranslatorMsg(),
            'parameters' => $this->getParameters(),
        ];
    }

    public function trans(TranslatorInterface $translator, string $locale = null): string
    {
        return $translator->trans($this->getMessage(), $this->getParameters(), 'validators', $locale);
    }
}
