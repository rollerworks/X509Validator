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

/**
 * @internal
 */
final class TranslatableArgument implements TranslatableInterface
{
    /** @param array<string, mixed> $parameters */
    public function __construct(
        private string $message,
        private array $parameters = [],
        private string $domain = 'validators',
    ) {
    }

    public function getMessage(): string
    {
        return $this->message;
    }

    /** @return array<string, mixed> */
    public function getParameters(): array
    {
        return $this->parameters;
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        return [
            'message' => $this->message,
            'parameters' => $this->parameters,
            'domain' => $this->domain,
        ];
    }

    /** @param array<string, mixed> $data */
    public function __unserialize(array $data): void
    {
        $this->message = $data['message'];
        $this->parameters = $data['parameters'];
        $this->domain = $data['domain'];
    }

    public function trans(TranslatorInterface $translator, ?string $locale = null): string
    {
        return $translator->trans($this->getMessage(), $this->getParameters(), $this->domain, $locale);
    }
}
