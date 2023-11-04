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

use Ocsp\Response;
use Ocsp\Response as OscpResponse;
use Rollerworks\Component\X509Validator\TranslatableArgument;
use Rollerworks\Component\X509Validator\Violation;

final class CertificateIsRevoked extends Violation
{
    // https://security.stackexchange.com/questions/174327/definitions-for-crl-reasons
    //
    // - unspecified: can be used to revoke certificates for reasons other than the specific codes.
    // - keyCompromise: is used in revoking an end-entity certificate; it indicates that it is known or suspected that the subject's private key, or other aspects of the subject validated in the certificate, have been compromised.
    // - cACompromise: is used in revoking a CA-certificate; it indicates that it is known or suspected that the subject's private key, or other aspects of the subject validated in the certificate, have been compromised.
    // - affiliationChanged: indicates that the subject's name or other information in the certificate has been modified but there is no cause to suspect that the private key has been compromised.
    // - superseded: indicates that the certificate has been superseded but there is no cause to suspect that the private key has been compromised.
    // - cessationOfOperation: indicates that the certificate is no longer needed for the purpose for which it was issued but there is no cause to suspect that the private key has been compromised.
    // - certificateHold: A temporary revocation that indicates that a CA will not vouch for a certificate at a specific point in time. Once a certificate is revoked with a CertificateHold reason code, the certificate can then be revoked with another Reason Code, or unrevoked and returned to use.
    // - removeFromCRL: If a certificate is revoked with the CertificateHold reason code, it is possible to "unrevoke" a certificate. The unrevoking process still lists the certificate in the CRL, but with the reason code set to RemoveFromCRL.
    // - privilegeWithdrawn: indicates that a certificate (public-key or attribute certificate) was revoked because a privilege contained within that certificate has been withdrawn.
    // - aACompromise: indicates that it is known or suspected that aspects of the AA validated in the attribute certificate have been compromised.

    private const REVOCATION_REASON = [
        Response::REVOCATIONREASON_UNSPECIFIED => 'unspecified',
        Response::REVOCATIONREASON_KEYCOMPROMISE => 'keyCompromise',
        Response::REVOCATIONREASON_CACOMPROMISE => 'cACompromise',
        Response::REVOCATIONREASON_AFFILIATIONCHANGED => 'affiliationChanged',
        Response::REVOCATIONREASON_SUPERSEDED => 'superseded',
        Response::REVOCATIONREASON_CESSATIONOFOPERATION => 'cessationOfOperation',
        Response::REVOCATIONREASON_CERTIFICATEHOLD => 'certificateHold',
        Response::REVOCATIONREASON_REMOVEFROMCRL => 'removeFromCRL',
        Response::REVOCATIONREASON_PRIVILEGEWITHDRAWN => 'privilegeWithdrawn',
        Response::REVOCATIONREASON_AACOMPROMISE => 'aACompromise',
    ];

    private const TRANSLATOR_ID = [
        'unspecified' => 'unspecified (no specific reason was given).',
        'keyCompromise' => 'the private key associated with the certificate has been compromised.',
        'cACompromise' => 'the CA\'s private key is has been compromised and is in the possession of an unauthorized individual. When a CA\'s private key is revoked, this results in all certificates issued by the CA that are signed using the private key associated with the revoked certificate being considered revoked.',
        'affiliationChanged' => 'the user has terminated their relationship with the organization indicated in the Distinguished Name attribute of the certificate. This revocation code is typically used when an individual is terminated or has resigned from an organization.',
        'superseded' => 'a replacement certificate has been issued to a user.',
        'cessationOfOperation' => 'the CA is decommissioned, no longer to be used.',
        'certificateHold' => 'the certificate is currently on hold, try again later',
        'removeFromCRL' => 'certificate revocation is removed', // This might possible not be an error
        'privilegeWithdrawn' => 'the certificate (public-key or attribute certificate) was revoked because a privilege contained within that certificate has been withdrawn.',
        'aACompromise' => 'it is known or suspected that aspects of the AA validated in the attribute certificate have been compromised.',
    ];

    private readonly ?\DateTimeInterface $revokedOn;
    private readonly ?int $reason;
    private readonly string $serial;

    public function __construct(?\DateTimeInterface $revokedOn, ?int $reason, string $serialNumber, public ?OscpResponse $ocspResponse = null)
    {
        parent::__construct(
            sprintf(
                'The certificate with serialNumber "%s" is revoked on "%s" due to reason "%s".',
                $serialNumber,
                $revokedOn ? $revokedOn->format(\DATE_RFC3339) : 'no-date',
                $reason
            )
        );

        $this->revokedOn = $revokedOn;
        $this->reason = $reason;
        $this->serial = $serialNumber;
    }

    public function getTranslatorMsg(): string
    {
        return 'The certificate with serial-number "{serial}" was marked as revoked on { revoked_on, date, short } with reason: ({reason_code}) {reason}.';
    }

    public function getParameters(): array
    {
        return [
            'revoked_on' => $this->revokedOn,
            'reason_code' => (self::REVOCATION_REASON[$this->reason] ?? 'unspecified'),
            'reason' => new TranslatableArgument(self::TRANSLATOR_ID[self::REVOCATION_REASON[$this->reason] ?? 'unspecified']),
            'serial' => $this->serial,
        ];
    }
}
